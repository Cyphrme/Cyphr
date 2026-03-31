package malt

import "errors"

// Sentinel errors for MALT operations.
var (
	ErrEmptyTree        = errors.New("malt: empty tree")
	ErrIndexOutOfBounds = errors.New("malt: index out of bounds")
	ErrInvalidOldSize   = errors.New("malt: invalid old size")
)
