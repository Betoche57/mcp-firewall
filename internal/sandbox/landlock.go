package sandbox

import "errors"

// ErrLandlockUnsupported is returned on platforms without Landlock.
var ErrLandlockUnsupported = errors.New("Landlock is not supported on this platform")
