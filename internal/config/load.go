package config

import (
	"os"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
)

// Load decodes, normalizes, and validates a YAML or JSON document.
func Load(data []byte) (*model.State, error) {
	st, err := Decode(data)
	if err != nil {
		return nil, err
	}
	n, err := Normalize(st)
	if err != nil {
		return nil, err
	}
	if err := Validate(n); err != nil {
		return nil, err
	}
	return n, nil
}

// LoadFile reads path and calls Load.
func LoadFile(path string) (*model.State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
