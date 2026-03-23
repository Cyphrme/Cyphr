package daolfmt

import "errors"

// Sentinel errors for DAOLFMT operations.
var (
	ErrEmptyTree        = errors.New("daolfmt: empty tree")
	ErrIndexOutOfBounds = errors.New("daolfmt: index out of bounds")
	ErrInvalidOldSize   = errors.New("daolfmt: invalid old size")
)
