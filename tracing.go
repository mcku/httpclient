package httpclient

import (
	"encoding/json"
	"fmt"
)

func debugPrintJSON(v interface{}) {

	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		fmt.Printf("JSON:\n\n%s\n\n", string(data))
		fmt.Printf("GO:\n\n%#v\n\n", v)
	} else {
		fmt.Printf("%s\n\n", string(data))

	}

}
