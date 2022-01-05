package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseYAMLConfigErrors(t *testing.T) {
	table := []struct {
		input string
		err   string
	}{
		{
			err:   "failed parsing YAML",
			input: "asdf",
		},
		{
			err:   "default coverage is outside the range 0-100",
			input: "default: 101",
		},
		{
			err: "coverage is outside the range 0-100 in",
			input: `
				default: 99
				functions:
				  - regex: asdf
				    coverage: 1234`,
		},
		{
			err: "coverage is outside the range 0-100 in",
			input: `
				default: 99
				filenames:
				  - regex: asdf
				    coverage: -1`,
		},
	}
	for _, test := range table {
		// This is ugly but it's the only way I've found to get reasonable
		// indentation.
		yml := strings.ReplaceAll(test.input, "\t", "")
		_, err := parseYAMLConfig([]byte(yml))
		if assert.Error(t, err) {
			// Note: the error message seems mangled when it's printed here, but it's
			// fine when printed for real.  I don't understand why and an hour of
			// debugging has gotten me nowhere :(
			assert.Contains(t, err.Error(), test.err, yml)
		}
	}
}

func TestParseYAMLConfigSuccess(t *testing.T) {
	config, err := parseYAMLConfig([]byte(""))
	assert.Nil(t, err)
	assert.Equal(t, 0.0, config.Default)

	yml := `
default: 75
functions:
	- regex: pinky
		coverage: 20
		comment: nobody understands pinky
	- regex: the brain
		coverage: 90
		comment: the brain thinks he's understood
filenames:
	- regex: main.go
		coverage: 50
	- regex: utils.go
		coverage: 95
`
	yml = strings.ReplaceAll(yml, "\t", "  ")
	config, err = parseYAMLConfig([]byte(yml))
	assert.Nil(t, err)
	assert.Equal(t, 75.0, config.Default)
	assert.Equal(t, 2, len(config.Functions))
	assert.Equal(t, "pinky", config.Functions[0].Regex)
}
