package ref

func Ref[k any](input k) *k {
	return &input
}

func RefOrEmptyNil(input string) *string {
	if input == "" {
		return nil
	}
	return &input
}

func RefOrNilNil(input interface{}) *interface{} {
	if input == nil {
		return nil
	}
	return &input
}

func DeRefOr[k any](input *k, def k) k {
	if input == nil {
		return def
	}
	return *input
}
