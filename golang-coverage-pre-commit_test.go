package main

import (
	"fmt"
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

func TestParseCoverageOutputSuccess(t *testing.T) {
	input := strings.Trim(`
github.com/.../golang-coverage-pre-commit.go:26:		String			100.0%
github.com/.../golang-coverage-pre-commit.go:48:		String			0.0%
github.com/.../golang-coverage-pre-commit.go:53:		makeExampleConfig	0.0%
github.com/.../golang-coverage-pre-commit.go:95:		parseYAMLConfig		100.0%
github.com/.../golang-coverage-pre-commit.go:118:	realMain		0.0%
github.com/.../golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`, "\n")
	results, err := parseCoverageOutput(strings.Split(input, "\n"))
	assert.Nil(t, err)
	assert.Equal(t, 6, len(results))

	// TODO: Add validation of results.
}

func TestParseCoverageOutputFailure(t *testing.T) {
	badInputLine := strings.Trim(`
github.com/.../golang-coverage-pre-commit.go:26:		String			100.0%
asdf
github.com/.../golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`, "\n")
	_, err := parseCoverageOutput(strings.Split(badInputLine, "\n"))
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "expected 3 parts, found 1")
	}

	table := []struct {
		input string
		err   string
	}{
		{
			err:   "could not extract percentage from",
			input: "1.2",
		},
		{
			err:   "could not extract percentage from",
			input: "qwerty",
		},
		{
			err:   "strconv.ParseFloat: parsing",
			input: "asdf%",
		},
		{
			err:   "percentage < 0",
			input: "-12.2%",
		},
		{
			err:   "percentage > 100",
			input: "105.3%",
		},
	}
	for _, test := range table {
		input := fmt.Sprintf("foo.go:26:		String			%s", test.input)
		_, err := parseCoverageOutput([]string{input})
		if assert.Error(t, err, test.input) {
			assert.Contains(t, err.Error(), test.err)
		}
	}
}

func TestMakeExampleConfig(t *testing.T) {
	expected := strings.TrimLeft(`
comment: Comment is not interpreted or used; it is provided as a structured way of
    adding comments to a config, so that automated editing is easier.
default: 80
functions:
  - comment: Low coverage is acceptable for main()
    regex: ^main$
    coverage: 50
  - comment: All the fooOrDie() functions should be fully tested because they panic()
        on failure
    regex: ^.*OrDie$
    coverage: 50
filenames:
  - comment: 'TODO: improve test coverage for parse_json.go'
    regex: ^parse_json.go$
    coverage: 73
  - comment: Full coverage for other parsers
    regex: ^parse.*.go$
    coverage: 100
`, "\n")
	assert.Equal(t, expected, makeExampleConfig())
}
