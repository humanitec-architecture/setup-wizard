package utils

import "encoding/json"

func ReEncode(v interface{}, t interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, t)
}
