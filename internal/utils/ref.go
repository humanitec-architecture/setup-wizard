package utils

func Ref[k any](input k) *k {
	return &input
}

func DeRefOr[k any](input *k, def k) k {
	if input == nil {
		return def
	}
	return *input
}
