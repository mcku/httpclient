package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"money-transfer/money-transfer-twcollector-service/utils"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"
)

var (
	userAgent = runtime.Version()
)

const (
	mediaType = "application/json"

	headerRateLimit     = "X-RateLimit-Limit"
	headerRateRemaining = "X-RateLimit-Remaining"
	headerRateReset     = "X-RateLimit-Reset"
	headerRequestID     = "X-Request-ID"
)

type HttpClient struct {
	client *http.Client

	BaseURL *url.URL

	UserAgent string

	Rate Rate

	// Optional function called after every successful request
	onRequestCompleted RequestCompletionCallback

	// trace dump
	Debug bool
}

// RequestCompletionCallback defines the type of the request callback function
type RequestCompletionCallback func(*http.Request, *http.Response)

// Response is an API response. This wraps the standard http.Response returned from the API.
type Response struct {
	*http.Response

	Rate
}

type ErrorResponseDecoder interface {
	// keep compatible with json decoder naming
	Error() string
	RawErrorStr() string
	Decode(errData []byte, errV interface{}) error
}

type errorResponseDecoder struct {
	ErrorResponse
}

// An ErrorResponse reports the error caused by an API request
type ErrorResponse struct {
	// HTTP response that caused this error
	Response *http.Response
	// Raw error response in case error doesn't fit known structure
	Raw string
	// Type is the error group name (auth_error, request_error, api_error, external_error vs..)
	Type string `json:"type"`
	// Code is the error short name (invalid_id, user_not_found)
	Code string `json:"code"`
	// Message is the human readable form of the error message
	Message string `json:"message"`

	// RequestID returned from the API, useful to contact support.
	RequestID string `json:"request_id"`
}

// Rate contains the rate limit for the current client.
type Rate struct {
	// The number of request per hour the client is currently limited to.
	Limit int `json:"limit"`

	// The number of remaining requests the client can make this hour.
	Remaining int `json:"remaining"`

	// The time at which the current rate limit will reset.
	Reset Timestamp `json:"reset"`
}

func NewHttpClient(baseURL *url.URL, insecureSkipVerify bool) *HttpClient {
	var client *http.Client
	if baseURL.Scheme == "https" {
		tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: insecureSkipVerify}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
	} else {
		client = http.DefaultClient
	}

	return &HttpClient{client: client, BaseURL: baseURL, UserAgent: userAgent}
}

// ClientOpt are options for New.
type ClientOpt func(*HttpClient) error

// New returns a new HTTP client instance.
func New(base string, insecureSkipVerify bool, opts ...ClientOpt) (*HttpClient, error) {

	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, err
	}

	c := NewHttpClient(baseURL, insecureSkipVerify)
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// SetBaseURL is a client option for setting the base URL.
func SetBaseURL(bu string) ClientOpt {
	return func(c *HttpClient) error {
		u, err := url.Parse(bu)
		if err != nil {
			return err
		}

		c.BaseURL = u
		return nil
	}
}

// SetUserAgent is a client option for setting the user agent.
func SetUserAgent(ua string) ClientOpt {
	return func(c *HttpClient) error {
		c.UserAgent = fmt.Sprintf("%s+%s", ua, c.UserAgent)
		return nil
	}
}

// Request-Response trace dumps on stdout
func SetTracingEnabled() ClientOpt {
	return func(c *HttpClient) error {
		c.Debug = true
		return nil
	}
}

// NewRequest creates an API request. A relative URL can be provided in urlStr, which will be resolved to the
// BaseURL of the Client. Relative URLS should always be specified without a preceding slash. If specified, the
// value pointed to by body is JSON encoded and included in as the request body.
func (c *HttpClient) NewRequest(ctx context.Context, method string, urlStr string, body interface{}, opts ...RequestOpt) (*http.Request, error) {
	rel, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	u := c.BaseURL.ResolveReference(rel)

	buf := new(bytes.Buffer)
	if body != nil {
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		if err := opt(req); err != nil {
			return nil, err
		}
	}

	if c.Debug {
		// pretty print v
		fmt.Printf("********************************************************************************\n\n")
		fmt.Printf("Request %s %s - %s\n\n", req.Method, req.URL.String(), time.Now().Format(time.RFC3339))
		debugPrintJSON(body)
		fmt.Printf("\n\n")
		fmt.Printf("********************************************************************************\n\n")
	}

	req.Header.Add("Content-Type", mediaType)
	req.Header.Add("Accept", mediaType)
	req.Header.Add("User-Agent", c.UserAgent)
	if id, ok := ctx.Value("Request-ID").(string); ok {
		req.Header.Add(headerRequestID, id)
	}
	return req, nil
}

// RequestOpt are options for New.
type RequestOpt func(*http.Request) error

// SetHeader option for setting the a header in the request
func SetHeader(key string, value string) RequestOpt {
	return func(r *http.Request) error {
		r.Header.Add(key, value)
		return nil
	}
}

func SetBearerToken(token string) RequestOpt {
	return SetHeader("Authorization", fmt.Sprintf("Bearer %s", token))
}

func SetBasicAuthentication(username string, password string) RequestOpt {
	return func(r *http.Request) error {
		r.SetBasicAuth(username, password)
		return nil
	}
}

// OnRequestCompleted sets the API request completion callback
func (c *HttpClient) OnRequestCompleted(rc RequestCompletionCallback) {
	c.onRequestCompleted = rc
}

// newResponse creates a new Response for the provided http.Response
func newResponse(r *http.Response) *Response {
	response := Response{Response: r}
	response.populateRate()

	return &response
}

// populateRate parses the rate related headers and populates the response Rate.
func (r *Response) populateRate() {
	if limit := r.Header.Get(headerRateLimit); limit != "" {
		r.Rate.Limit, _ = strconv.Atoi(limit)
	}
	if remaining := r.Header.Get(headerRateRemaining); remaining != "" {
		r.Rate.Remaining, _ = strconv.Atoi(remaining)
	}
	if reset := r.Header.Get(headerRateReset); reset != "" {
		if v, _ := strconv.ParseInt(reset, 10, 64); v != 0 {
			r.Rate.Reset = Timestamp{time.Unix(v, 0)}
		}
	}
}

// Do sends an API request and returns the API response. The API response is JSON decoded and stored in the value
// pointed to by v, or returned as an error if an API error has occurred. If v implements the io.Writer interface,
// the raw response will be written to v, without attempting to decode it.
func (c *HttpClient) Do(req *http.Request, v interface{}, errV interface{}) (*Response, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if c.onRequestCompleted != nil {
		c.onRequestCompleted(req, resp)
	}

	defer func() {
		if rerr := resp.Body.Close(); err == nil {
			err = rerr
		}
	}()

	response := newResponse(resp)
	c.Rate = response.Rate

	err = CheckResponse(resp, errV)
	if err != nil {
		if c.Debug {
			// pretty print errV
			fmt.Printf("********************************************************************************\n\n")
			fmt.Printf("Response (Error part) %s %s - %s\n\n", req.Method, req.URL.String(), time.Now().Format(time.RFC3339))
			debugPrintJSON(errV)
			fmt.Printf("Response (Non error part) - %s\n\n", time.Now().Format(time.RFC3339))
			rawData, _ := ioutil.ReadAll(resp.Body)
			debugPrintJSON(rawData)
			fmt.Printf("********************************************************************************\n\n")
		}
		return response, err
	}

	if c.Debug {
		// pretty print v
		fmt.Printf("********************************************************************************\n\n")
		fmt.Printf("Response %s %s - %s\n\n", req.Method, req.URL.String(), time.Now().Format(time.RFC3339))
	}
	rawData, _ := ioutil.ReadAll(resp.Body)
	if v != nil {
		if w, ok := v.(io.Writer); ok {
			reader := bytes.NewReader(rawData)
			_, err = io.Copy(w, reader)
			if c.Debug {
				debugPrintJSON(w)
				fmt.Printf("********************************************************************************\n\n")
			}
		} else {
			reader := bytes.NewReader(rawData)
			err = json.NewDecoder(reader).Decode(v)
			if c.Debug {
				var m interface{} = map[string]interface{}{}
				reader := bytes.NewReader(rawData)
				if err := json.NewDecoder(reader).Decode(&m); err != nil {
					fmt.Printf("\nDecoding into %s had errors, displaying raw data instead:\n", utils.ToJSON(v))
					fmt.Printf("%s\n\n", string(rawData))
				} else {
					debugPrintJSON(m)
				}
				fmt.Printf("********************************************************************************\n\n")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return response, err
}

func (r *ErrorResponse) Error() string {
	if r.RequestID != "" {
		return fmt.Sprintf("%v %v: %d (request %q) %v",
			r.Response.Request.Method, r.Response.Request.URL, r.Response.StatusCode, r.RequestID, r.Message)
	}
	if r.Message == "" {
		return r.Raw
	}
	return fmt.Sprintf("[%d] %v %v: %v",
		r.Response.StatusCode, r.Response.Request.Method, r.Response.Request.URL, r.Message)
}

// CheckResponse checks the API response for errors, and returns them if present. A response is considered an
// error if it has a status code outside the 200 range. API error responses are expected to have either no response
// body, or a JSON response body that maps to ErrorResponse. Any other response body will be silently ignored.
func CheckResponse(r *http.Response, errV interface{}) ErrorResponseDecoder {
	if c := r.StatusCode; c >= 200 && c <= 299 {
		return nil
	}

	errorResponse := &errorResponseDecoder{ErrorResponse{Response: r}}
	data, err := ioutil.ReadAll(r.Body)
	if err == nil && len(data) > 0 {
		if errV == nil {
			err = json.Unmarshal(data, errorResponse)
		} else {
			err = errorResponse.Decode(data, errV)
		}
		errorResponse.Raw = string(data)

		// keeping this for verbosity
		if err != nil {
			// Silently skip when response body doesn't fit errorresponse structure
			return errorResponse
		}
	}
	errorResponse.Raw = string(data)
	return errorResponse

}

// Decode decode into errV. Make sure that errV is not nil
func (e *errorResponseDecoder) Decode(data []byte, errV interface{}) error {
	return json.Unmarshal(data, errV)
}

func (e *errorResponseDecoder) RawErrorStr() string {
	return e.Raw
}

func (r Rate) String() string {
	return Stringify(r)
}

// String is a helper routine that allocates a new string value
// to store v and returns a pointer to it.
func String(v string) *string {
	p := new(string)
	*p = v
	return p
}

// Int is a helper routine that allocates a new int32 value
// to store v and returns a pointer to it, but unlike Int32
// its argument value is an int.
func Int(v int) *int {
	p := new(int)
	*p = v
	return p
}

// Bool is a helper routine that allocates a new bool value
// to store v and returns a pointer to it.
func Bool(v bool) *bool {
	p := new(bool)
	*p = v
	return p
}

// StreamToString converts a reader to a string
func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(stream)
	return buf.String()
}

//
// http request helper functions
//

// helper function for making an http GET request.
func (c *HttpClient) Get(ctx context.Context, path string, out interface{}, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	req, err := c.NewRequest(ctx, "GET", path, nil, opts...)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req, out, errOut)
	if err != nil {
		return resp, err
	}

	return resp, err
}

// helper function for making an http POST request.
func (c *HttpClient) Post(ctx context.Context, path string, in, out interface{}, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	req, err := c.NewRequest(ctx, "POST", path, in, opts...)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req, out, errOut)
	if err != nil {
		return resp, err
	}

	return resp, err
}

// helper function for making an http PUT request.
func (c *HttpClient) Put(ctx context.Context, path string, in, out interface{}, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	if in == nil {
		return nil, NewArgError("PUT body", "cannot be nil")
	}

	req, err := c.NewRequest(ctx, "PUT", path, in, opts...)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req, out, errOut)
	if err != nil {
		return resp, err
	}

	return resp, err
}

// helper function for making an http PATCH request.
func (c *HttpClient) Patch(ctx context.Context, path string, in, out interface{}, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	if in == nil {
		return nil, NewArgError("PATCH body", "cannot be nil")
	}

	req, err := c.NewRequest(ctx, "PATCH", path, in, opts...)
	if err != nil {
		return nil, err
	}

	resp, err := c.Do(req, out, errOut)
	if err != nil {
		return resp, err
	}

	return resp, err
}

// helper function for making an http DELETE request.
func (c *HttpClient) Delete(ctx context.Context, path string, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	req, err := c.NewRequest(ctx, "DELETE", path, nil, opts...)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req, nil, errOut)
	if err != nil {
		return resp, err
	}

	return resp, err
}

// Use this for making generic http requests with context
func (c *HttpClient) DoWithContext(ctx context.Context, method string, path string, in interface{}, out interface{}, errOut interface{}, opts ...RequestOpt) (*Response, error) {
	switch method {
	case "GET":
		return c.Get(ctx, path, out, errOut, opts...)
	case "POST":
		return c.Post(ctx, path, in, out, errOut, opts...)
	case "PUT":
		return c.Put(ctx, path, in, out, errOut, opts...)
	case "PATCH":
		return c.Patch(ctx, path, in, out, errOut, opts...)
	case "DELETE":
		return c.Delete(ctx, path, errOut, opts...)
	}
	return nil, fmt.Errorf("DoWithContext: Unknown method %s", method)
}
