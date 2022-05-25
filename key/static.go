package key

// Static implements a Key Provider which returns a fixed set of keys.
type Static struct {
	keys Keys
}

// NewStatic creates a new Static key provider which returns the given Keys.
func NewStatic(keys Keys) Static {
	return Static{keys}
}

// GetKeys returns the static set of keys.
func (s *Static) GetKeys() (Keys, error) {
	return s.keys, nil
}
