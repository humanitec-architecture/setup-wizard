package utils

import (
	"regexp"
)

var humanitecIdRegex = regexp.MustCompile(`^[a-z0-9](?:-?[a-z0-9]+)+$`)

func IsValidHumanitecId(id string) bool {
	return humanitecIdRegex.MatchString(id)
}
