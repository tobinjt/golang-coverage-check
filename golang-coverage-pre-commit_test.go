package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			err:   "default coverage (101.0) is outside the range 0-100",
			input: "default: 101",
		},
		{
			err: "coverage (1234.0) is outside the range 0-100 in",
			input: `
				default: 99
				functions:
				  - regex: asdf
				    coverage: 1234`,
		},
		{
			err: "coverage (-1.0) is outside the range 0-100 in",
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

func TestParseCoverageOutputSuccess(t *testing.T) {
	input := `
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:26:		String			100.0%
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:48:		String			31.0%
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:53:		makeExampleConfig	50.0%
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:95:		parseYAMLConfig		100.0%
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:118:	realMain		17.3%
github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`
	options := newOptions()
	options.modulePath = "github.com/tobinjt/golang-coverage-pre-commit/"
	results, err := parseCoverageOutput(options, strings.Split(input, "\n"))
	assert.Nil(t, err)
	assert.Equal(t, 6, len(results))

	expected := []CoverageLine{
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "26",
			Function:   "String",
			Coverage:   100.0,
		},
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "48",
			Function:   "String",
			Coverage:   31.0,
		},
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "53",
			Function:   "makeExampleConfig",
			Coverage:   50.0,
		},
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "95",
			Function:   "parseYAMLConfig",
			Coverage:   100.0,
		},
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "118",
			Function:   "realMain",
			Coverage:   17.3,
		},
		{
			Filename:   "golang-coverage-pre-commit.go",
			LineNumber: "140",
			Function:   "main",
			Coverage:   0.0,
		},
	}
	assert.Equal(t, expected, results)
}

func TestParseCoverageOutputFailure(t *testing.T) {
	options := newOptions()

	badInputLine := `
github.com/.../golang-coverage-pre-commit.go:26:		String			100.0%
asdf
github.com/.../golang-coverage-pre-commit.go:140:	main			0.0%
total:											(statements)		38.1%
`
	_, err := parseCoverageOutput(options, strings.Split(badInputLine, "\n"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 parts, found 1")

	badInputLine = `missing-line-number:		String			100.0%`
	_, err = parseCoverageOutput(options, []string{badInputLine})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected `filename:linenumber:` in \"missing-line-number:\"")

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
			err:   "percentage (-12.2) < 0",
			input: "-12.2%",
		},
		{
			err:   "percentage (105.3) > 100",
			input: "105.3%",
		},
	}
	for _, test := range table {
		input := fmt.Sprintf("foo.go:26:		String			%s", test.input)
		_, err := parseCoverageOutput(options, []string{input})
		if assert.Error(t, err, test.input) {
			assert.Contains(t, err.Error(), test.err)
		}
	}
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
		debug  []string
	}{
		{
			desc:   "Function matching",
			errors: []string{"utils.go:1:\tReadFileOrDie\t57.0%: coverage 57.0% < 100.0%: matching function rule"},
			debug: []string{
				"Debug info for coverage matching",
				"Line utils.go:1:\tReadFileOrDie\t57.0%\n",
				"Function match: Regex: OrDie$ Coverage: 100",
			},
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
				"parse_json.go:1:\tFoo\t53.0%: coverage 53.0% < 73.0%: matching filename rule is",
				"parse_yaml.go:1:\tBaz\t83.0%: coverage 83.0% < 100.0%: matching filename rule is",
			},
			debug: []string{
				"Line parse_json.go:1:\tFoo\t53.0%\n",
				"Filename match: Regex: ^parse_json.go$ Coverage: 73",
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
			errors: []string{"utils.go:1:\tFoo\t57.0%: coverage 57.0% < 80.0%: default coverage requirement 80.0%"},
			debug:  []string{"Line utils.go:1:\tFoo\t57.0%\n  - Default coverage not satisfied"},
			input: `
// Matches nothing, coverage too low.
utils.go:1:	Foo	57.0%
// Matches nothing, coverage acceptable.
utils.go:1:	Bar	100.0%
`,
		},
		{
			desc:   "No errors found",
			errors: []string{},
			debug:  []string{"Line utils.go:1:\tBar\t100.0%\n  - Default coverage satisfied"},
			input: `
// Matches nothing, coverage acceptable.
utils.go:1:	Bar	100.0%
`,
		},
	}

	options := newOptions()
	for _, test := range tests {
		coverage, err := parseCoverageOutput(options, splitAndStripComments(test.input))
		assert.Nil(t, err)
		debug, err := checkCoverage(config, coverage)
		if len(test.errors) == 0 {
			assert.Nil(t, err)
		}
		for i := range test.errors {
			assert.Contains(t, err.Error(), test.errors[i], test.desc)
		}
		for i := range test.debug {
			assert.Contains(t, debug, test.debug[i], test.desc)
		}
	}
}

func TestRealMainSimpleFailures(t *testing.T) {
	table := []struct {
		desc   string
		err    string
		output string
		mod    func(opts Options) Options
	}{
		{
			desc:   "makeExampleConfig",
			err:    "",
			output: "Comment is not interpreted or used",
			mod: func(opts Options) Options {
				opts.outputExampleConfig = true
				return opts
			},
		},
		{
			desc:   "bad go.mod path",
			err:    "failed reading go-mod-does-not-exist:",
			output: "",
			mod: func(opts Options) Options {
				opts.goMod = "go-mod-does-not-exist"
				return opts
			},
		},
		{
			desc:   "bad config path",
			err:    "failed reading config does-not-exist.yaml:",
			output: "",
			mod: func(opts Options) Options {
				opts.configFile = "does-not-exist.yaml"
				return opts
			},
		},
		{
			desc:   "bad config contents",
			err:    "failed parsing config bad-config.yaml:",
			output: "",
			mod: func(opts Options) Options {
				opts.configFile = "bad-config.yaml"
				return opts
			},
		},
		{
			desc:   "unexpected arguments",
			err:    "unexpected arguments",
			output: "",
			mod: func(opts Options) Options {
				opts.args = []string{"asdf", "1234"}
				return opts
			},
		},
		{
			desc:   "goCover fails",
			err:    "forced error for goCover fails",
			output: "",
			mod: func(opts Options) Options {
				opts.createTemp = func(_, __ string) (*os.File, error) {
					return nil, fmt.Errorf("forced error for goCover fails")
				}
				return opts
			},
		},
		{
			desc:   "parseCoverageOutput fails",
			err:    "expected 3 parts, found 1, in \"qwerty\"",
			output: "",
			mod: func(opts Options) Options {
				opts.captureOutput = func(string, ...string) ([]string, error) {
					return []string{"qwerty"}, nil
				}
				return opts
			},
		},
	}

	for _, test := range table {
		options := test.mod(newOptions())
		output, err := realMain(options)
		if len(test.err) == 0 {
			assert.Nil(t, err, test.desc)
		} else {
			assert.Error(t, err, test.desc)
			assert.Contains(t, err.Error(), test.err, test.desc)
		}
		if len(test.output) > 0 {
			assert.Contains(t, output, test.output, test.desc)
		} else {
			assert.Equal(t, "", output)
		}
	}
}
