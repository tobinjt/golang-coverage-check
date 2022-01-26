package main

import (
	"errors"
	"fmt"
	"os"
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
	input := `
github.com/.../golang-coverage-pre-commit.go:26:		String			100.0%
github.com/.../golang-coverage-pre-commit.go:48:		String			31.0%
github.com/.../golang-coverage-pre-commit.go:53:		makeExampleConfig	50.0%
github.com/.../golang-coverage-pre-commit.go:95:		parseYAMLConfig		100.0%
github.com/.../golang-coverage-pre-commit.go:118:	realMain		17.3%
github.com/.../golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`
	results, err := parseCoverageOutput(strings.Split(input, "\n"))
	assert.Nil(t, err)
	assert.Equal(t, 6, len(results))

	expected := []CoverageLine{
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "String",
			Coverage: 100.0,
		},
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "String",
			Coverage: 31.0,
		},
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "makeExampleConfig",
			Coverage: 50.0,
		},
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "parseYAMLConfig",
			Coverage: 100.0,
		},
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "realMain",
			Coverage: 17.3,
		},
		{
			Filename: "github.com/.../golang-coverage-pre-commit.go",
			Function: "main",
			Coverage: 0.0,
		},
	}
	assert.Equal(t, expected, results)
}

func TestParseCoverageOutputFailure(t *testing.T) {
	badInputLine := `
github.com/.../golang-coverage-pre-commit.go:26:		String			100.0%
asdf
github.com/.../golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`
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
    regex: OrDie$
    coverage: 100
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

func splitAndStripComments(input string) []string {
	output := []string{}
	for _, line := range strings.Split(input, "\n") {
		if !strings.HasPrefix(line, "//") {
			output = append(output, line)
		}
	}
	return output
}

func TestCheckCoverage(t *testing.T) {
	config, err := parseYAMLConfig([]byte(makeExampleConfig()))
	assert.Nil(t, err)
	config.Comment = "Config for testing checkCoverage()"

	tests := []struct {
		input  string
		desc   string
		errors []string
	}{
		{
			desc:   "Function matching",
			errors: []string{"coverage is too low: 57.0 < 100.0"},
			input: `
// Matches OrDie$, coverage too low.
utils.go:1:	ReadFileOrDie	57.0%
// Matches OrDie$, coverage acceptable.
utils.go:1:	ParseIntOrDie	100.0%
`,
		},
		{
			desc: "Filename matching",
			errors: []string{
				"coverage is too low: 53.0 < 73.0:",
				"coverage is too low: 83.0 < 100.0",
			},
			input: `
// Matches ^parse_json.go$, coverage too low.
parse_json.go:1:	Foo	53.0%
// Matches ^parse_json.go$, coverage acceptable.  Ensures that ^parse.*.go$ isn't hit.
parse_json.go:1:	Bar	80.0%
// Matches ^parse_.*.go$, coverage too low.
parse_yaml.go:1:	Baz	83.0%
// Matches ^parse_.*.go$, coverage acceptable.
parse_yaml.go:1:	Qwerty	100.0%
`,
		},
		{
			desc:   "Default matching",
			errors: []string{"line utils.go:\tFoo\t57.0% did not meet default coverage requirement 80"},
			input: `
// Matches nothing, coverage too low.
utils.go:1:	Foo	57.0%
// Matches nothing, coverage acceptable.
utils.go:1:	Bar	100.0%
`,
		},
	}

	for _, test := range tests {
		coverage, err := parseCoverageOutput(splitAndStripComments(test.input))
		assert.Nil(t, err)
		errors, debugInfo := checkCoverage(config, coverage)
		messages := fmt.Sprintf("%s\n\n%v\n\n%s", test.desc, errors, strings.Join(debugInfo, "\n"))
		if assert.Equal(t, len(test.errors), len(errors), messages) {
			for i := range test.errors {
				assert.Contains(t, errors[i].Error(), test.errors[i])
			}
		}
	}
}

func TestCaptureOutput(t *testing.T) {
	output, err := captureOutput("cat", "/non-existent")
	assert.Error(t, err)
	assert.Empty(t, output)
	assert.Contains(t, err.Error(), "cat: /non-existent: No such file or directory")

	output, err = captureOutput("cat", "/etc/passwd")
	assert.Nil(t, err)
	rootLines := []string{}
	for _, line := range output {
		if strings.HasPrefix(line, "root:") {
			rootLines = append(rootLines, line)
		}
	}
	assert.Len(t, rootLines, 1)
}

func TestGoCoverSuccess(t *testing.T) {
	fakeOutput := map[string][]string{
		"test": []string{"completely", "ignored"},
		"tool": []string{"expected return value"},
	}
	options := newOptions()
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		return fakeOutput[args[0]], nil
	}
	actual, err := goCover(options)
	assert.Nil(t, err)
	assert.Equal(t, fakeOutput["tool"], actual)
}

func TestGoCoverCaptureFailure(t *testing.T) {
	options := newOptions()
	options.captureOutput = func(string, ...string) ([]string, error) {
		return []string{"this should not be seen"}, errors.New("error for testing")
	}
	actual, err := goCover(options)
	assert.Error(t, err)
	assert.Equal(t, []string{}, actual)
	assert.Contains(t, err.Error(), "error for testing")
}

func TestGoCoverCreateTempFailure(t *testing.T) {
	options := newOptions()
	options.createTemp = func(string, string) (*os.File, error) {
		return nil, errors.New("error for testing")
	}
	actual, err := goCover(options)
	assert.Error(t, err)
	assert.Equal(t, []string{}, actual)
	assert.Contains(t, err.Error(), "error for testing")
}
