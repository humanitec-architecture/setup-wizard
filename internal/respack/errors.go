package respack

import "errors"

var (
	ErrUnknownResourcePack      = errors.New("unknown resource pack")
	ErrResourcePackNotSupported = errors.New("resource pack not supported")
)
