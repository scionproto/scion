package ptr

// PointerTo generates a pointer to a variable containing the given value.
// In Go, addressible constant is an oxymoron, so the expression "&true", for example, is invalid.
// This function makes that less annoying.
func To[T any](v T) *T {
	return &v
}
