// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newTestOptions() Options {
	options := newOptions()
	options.rawArgs = []string{}
	options.captureOutput = func(string, ...string) ([]string, error) {
		panic("captureOutput was called without being set by the test")
	}
	return options
}

func TestMakeExampleConfig(t *testing.T) {
	expected := strings.Split(strings.TrimLeft(strings.ReplaceAll(`
comment: Comment is not interpreted or used; it is provided as a structured way of
	adding comments to a config, so that automated editing is easier.
default_coverage: 80
rules:
- comment: Low coverage is acceptable for main()
	filename_regex: ""
	function_regex: ^main$
	receiver_regex: ""
	coverage: 50
- comment: All the fooOrDie() functions should be fully tested because they panic()
		on failure
	filename_regex: ""
	function_regex: OrDie$
	receiver_regex: ""
	coverage: 100
- comment: Improve test coverage for parse_json.go?
	filename_regex: ^parse_json.go$
	function_regex: ""
	receiver_regex: ""
	coverage: 73
- comment: Full coverage for other parsers
	filename_regex: ^parse.*.go$
	function_regex: ""
	receiver_regex: ""
	coverage: 100
- comment: Url.String() has low coverage
	filename_regex: ^urls.go$
	function_regex: ^String$
	receiver_regex: ^Url$
	coverage: 56
- comment: String() everywhere else should have high coverage
	filename_regex: ""
	function_regex: ^String$
	receiver_regex: ""
	coverage: 100
`, "\t", "  "), "\n"), "\n")
	actual := strings.Split(makeExampleConfig()[0], "\n")
	assert.Equal(t, expected, actual)
}

func TestGenerateConfig(t *testing.T) {
	coverage := []CoverageLine{
		{
			Filename:   "test.go",
			LineNumber: "1",
			Function:   "func1",
			Coverage:   20.0,
		},
		{
			Filename:   "test.go",
			LineNumber: "2",
			Function:   "func5",
			Coverage:   34.0,
		},
		{
			Filename:   "test.go",
			LineNumber: "9",
			Function:   "func17",
			Coverage:   12.3,
		},
	}

	fim := FunctionInfoMap{
		"test.go:9": {
			Filename:   "test.go",
			LineNumber: "9",
			Function:   "func17",
			Receiver:   "receiver-receiver-receiver",
		},
	}

	expected := Config{
		DefaultCoverage: 100.0,
		Rules: []Rule{
			{
				FilenameRegex: "^test.go$",
				FunctionRegex: "^func1$",
				ReceiverRegex: "^$",
				Comment:       "Generated rule for func1, found at test.go:1",
				Coverage:      20.0,
			},
			{
				FilenameRegex: "^test.go$",
				FunctionRegex: "^func5$",
				ReceiverRegex: "^$",
				Comment:       "Generated rule for func5, found at test.go:2",
				Coverage:      34.0,
			},
			{
				FilenameRegex: "^test.go$",
				FunctionRegex: "^func17$",
				ReceiverRegex: "^receiver-receiver-receiver$",
				Comment:       "Generated rule for func17, found at test.go:9",
				Coverage:      12.3,
			},
		},
	}

	generated := generateConfig(coverage, fim)
	assert.Equal(t, expected, generated)
}

func TestValidateConfigErrors(t *testing.T) {
	table := []struct {
		config Config
		err    string
	}{
		{
			err: "default coverage (101.0) is outside the range 0-100",
			config: Config{
				DefaultCoverage: 101,
			},
		},
		{
			err: "default coverage (-1.0) is outside the range 0-100",
			config: Config{
				DefaultCoverage: -1,
			},
		},
		{
			err: "coverage (1234.0) is outside the range 0-100 in",
			config: Config{
				DefaultCoverage: 99,
				Rules: []Rule{
					{
						FilenameRegex: "asdf",
						Coverage:      1234,
					},
				},
			},
		},
		{
			err: "coverage (-1.0) is outside the range 0-100 in",
			config: Config{
				DefaultCoverage: 99,
				Rules: []Rule{
					{
						FilenameRegex: "asdf",
						Coverage:      -1,
					},
				},
			},
		},
		{
			err: "every regex is an empty string in rule",
			config: Config{
				DefaultCoverage: 99,
				Rules: []Rule{
					{
						Coverage: 1,
					},
				},
			},
		},
	}
	for _, test := range table {
		_, err := validateConfig(test.config)
		// Note: the error message seems mangled when it's printed here, but it's
		// fine when printed for real.  I don't understand why and an hour of
		// debugging has gotten me nowhere :(
		assert.ErrorContains(t, err, test.err, test.config)
	}
}

func TestValidateConfigSuccess(t *testing.T) {
	config := Config{
		Comment:         "successful test",
		DefaultCoverage: 75.0,
		Rules: []Rule{
			{
				Comment:       "successful rule",
				FilenameRegex: "foo",
				FunctionRegex: "bar",
				ReceiverRegex: "baz",
				Coverage:      7.0,
			},
		},
	}
	config, err := validateConfig(config)
	assert.Nil(t, err)
	assert.Equal(t, 75.0, config.DefaultCoverage)
	assert.Equal(t, 1, len(config.Rules))
	rule := config.Rules[0]
	assert.Equal(t, "foo", rule.FilenameRegex)
	assert.Equal(t, "bar", rule.FunctionRegex)
	assert.Equal(t, "baz", rule.ReceiverRegex)
	assert.NotNil(t, rule.compiledFilenameRegex)
	assert.NotNil(t, rule.compiledFunctionRegex)
	assert.NotNil(t, rule.compiledReceiverRegex)
}

func TestParseYAMLConfig_UnmarshalError(t *testing.T) {
	_, err := parseYAMLConfig([]byte("asdf"))
	assert.ErrorContains(t, err, "failed parsing YAML: yaml: unmarshal errors")
}

func TestParseYAMLConfigSuccess(t *testing.T) {
	config, err := parseYAMLConfig([]byte(""))
	assert.Nil(t, err)
	assert.Equal(t, 0.0, config.DefaultCoverage)

	yml := `
default_coverage: 75
rules:
	- function_regex: pinky
		coverage: 20
		comment: nobody understands pinky
	- function_regex: the brain
		coverage: 90
		comment: the brain thinks he's understood
	- filename_regex: main.go
		coverage: 50
	- filename_regex: utils.go
		coverage: 95
`
	yml = strings.ReplaceAll(yml, "\t", "  ")
	config, err = parseYAMLConfig([]byte(yml))
	assert.Nil(t, err)
	assert.Equal(t, 75.0, config.DefaultCoverage)
	assert.Equal(t, 4, len(config.Rules))
	assert.Equal(t, "pinky", config.Rules[0].FunctionRegex)
}

func TestMakeFunctionInfoMapFailure(t *testing.T) {
	options := newTestOptions()
	options.dirToParse = "does-not-exist"
	_, err := makeFunctionInfoMap(options)
	assert.Error(t, err)
}

func TestMakeFunctionInfoMapSuccess(t *testing.T) {
	fmap, err := makeFunctionInfoMap(newTestOptions())
	assert.Nil(t, err)
	fis := []FunctionInfo{
		{
			Filename:   "functions-for-testing-makeFunctionInfoMap.go",
			LineNumber: "20",
			Function:   "functionAtLine20",
			Receiver:   "",
		},
		{
			Filename:   "functions-for-testing-makeFunctionInfoMap.go",
			LineNumber: "26",
			Function:   "String",
			Receiver:   "methodReceiver",
		},
	}
	for _, fi := range fis {
		key := fi.key()
		if assert.Contains(t, fmap, key) {
			assert.Equal(t, fi, fmap[key])
		}
	}
}

func TestMakeFunctionInfoMapSupport(t *testing.T) {
	// Test that the functions in functions-for-testing-makeFunctionInfoMap.go
	// are correct so that other tests have known good data to work with.
	assert.Equal(t, "This function is at line 20 to test makeFunctionInfoMap()", functionAtLine20())
	mr := methodReceiver{}
	assert.Equal(t, "This method has a methodReceiver receiver to test makeFunctionInfoMap()", mr.String())
}

func TestCaptureOutput(t *testing.T) {
	output, err := captureOutput("cat", "/non-existent")
	assert.Nil(t, output)
	assert.ErrorContains(t, err, "cat: /non-existent: No such file or directory")

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

func TestReadLineWithRetry_Success(t *testing.T) {
	file, err := os.Open("go.mod")
	assert.Nil(t, err)
	line, err := readLineWithRetry(file)
	assert.Nil(t, err)
	assert.Equal(t, "module github.com/tobinjt/golang-coverage-check\n", line)
}

func TestReadLineWithRetry_EOF(t *testing.T) {
	file, err := os.CreateTemp("", "TestReadLineWithRetry_EOF.*")
	assert.Nil(t, err)
	strCh := make(chan string)
	errCh := make(chan error)
	runMe := func() {
		line, err := readLineWithRetry(file)
		strCh <- line
		errCh <- err
	}
	go runMe()

	time.Sleep(3 * sleepTime)
	length, err := file.WriteString("written to temp file\n")
	assert.Nil(t, err)
	assert.Greater(t, length, 10)
	// Sync and seek back to the start so that the read in the other goroutine
	// can complete.
	err = file.Sync()
	assert.Nil(t, err)
	offset, err := file.Seek(0, 0)
	assert.Nil(t, err)
	assert.Equal(t, int64(0), offset)

	line, err := <-strCh, <-errCh
	assert.Nil(t, err)
	assert.Equal(t, "written to temp file\n", line)
}

func TestReadLineWithRetry_Error(t *testing.T) {
	file, err := os.CreateTemp("", "TestReadLineWithRetry_Error.*")
	assert.Nil(t, err)
	strCh := make(chan string)
	errCh := make(chan error)
	runMe := func() {
		line, err := readLineWithRetry(file)
		strCh <- line
		errCh <- err
	}
	go runMe()
	time.Sleep(3 * sleepTime)
	file.Close()
	line, err := <-strCh, <-errCh
	assert.ErrorContains(t, err, "file already closed")
	assert.Equal(t, "", line)
}

func TestGoCoverCapturePathSuccess(t *testing.T) {
	options := newTestOptions()
	options.captureOutput = captureOutput
	coverageFile, err := options.createTemp("", "golang-coverage-check.*.coverage-data")
	assert.Nil(t, err)
	path, err := goCoverCapturePath(options, coverageFile.Name())
	assert.Nil(t, err)
	assert.Equal(t, 1, len(path))
}

func TestGoCoverCapturePath_CreateTempFailed(t *testing.T) {
	options := newTestOptions()
	options.createTemp = func(string, string) (*os.File, error) {
		return nil, errors.New("createTemp failed")
	}
	path, err := goCoverCapturePath(options, "")
	assert.Error(t, err)
	assert.Nil(t, path)
}

func TestGoCoverCapturePath_CreateTempFailedSecondTime(t *testing.T) {
	options := newTestOptions()
	calledBefore := false
	options.createTemp = func(dir, pattern string) (*os.File, error) {
		if calledBefore {
			return nil, errors.New("createTemp failed on second call")
		}
		calledBefore = true
		return os.CreateTemp(dir, pattern)
	}
	path, err := goCoverCapturePath(options, "")
	assert.Nil(t, path)
	assert.ErrorContains(t, err, "createTemp failed on second call")
}

func TestGoCoverCapturePath_ReadingFileFailed(t *testing.T) {
	options := newTestOptions()
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		return nil, nil
	}
	options.readLineWithRetry = func(*os.File) (string, error) {
		return "", errors.New("readLineWithRetry failed")
	}
	path, err := goCoverCapturePath(options, "")
	assert.Nil(t, path)
	assert.ErrorContains(t, err, "readLineWithRetry failed")
}

func TestGoCoverCapturePath_ChmodFailed(t *testing.T) {
	options := newTestOptions()
	options.chmod = func(*os.File, os.FileMode) error {
		return errors.New("chmod failed")
	}
	path, err := goCoverCapturePath(options, "")
	assert.Nil(t, path)
	assert.ErrorContains(t, err, "chmod failed")
}

func TestGoCoverCapturePath_SetenvFailed(t *testing.T) {
	options := newTestOptions()
	options.setenv = func(string, string) error {
		return errors.New("setenv failed")
	}
	path, err := goCoverCapturePath(options, "")
	assert.Nil(t, path)
	assert.ErrorContains(t, err, "setenv failed")
}

func TestGoCoverCapturePath_CaptureOutputFailed(t *testing.T) {
	options := newTestOptions()
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		return nil, errors.New("captureOutput failed")
	}
	path, err := goCoverCapturePath(options, "")
	assert.Nil(t, path)
	assert.ErrorContains(t, err, "captureOutput failed")
}

func TestGoCoverSuccess(t *testing.T) {
	fakeOutput := map[string][]string{
		"test --covermode set --coverprofile": {"ignored"},
		"tool cover --func":                   {"expected return value"},
	}
	commandRun := map[string]bool{}
	options := newTestOptions()
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		// The random filename is always the last arg, so drop it.
		parts := args[0 : len(args)-1]
		key := strings.Join(parts, " ")
		commandRun[key] = true
		return fakeOutput[key], nil
	}
	actual, _, err := goCover(options)
	assert.Nil(t, err)
	assert.Equal(t, []string{"expected return value"}, actual)
	assert.Equal(t, len(commandRun), 2)
	assert.True(t, commandRun["test --covermode set --coverprofile"], commandRun)
	assert.True(t, commandRun["tool cover --func"], commandRun)
}

func TestGoCoverBrowserFailure(t *testing.T) {
	fakeOutput := map[string][]string{
		"test --covermode set --coverprofile": {"ignored"},
	}
	fakeErrors := map[string]error{
		"tool cover --html": fmt.Errorf("browser error"),
	}
	commandRun := map[string]bool{}
	options := newTestOptions()
	options.coverageHTML = htmlOpenInBrowser
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		// The random filename is always the last arg, so drop it.
		parts := args[0 : len(args)-1]
		key := strings.Join(parts, " ")
		commandRun[key] = true
		return fakeOutput[key], fakeErrors[key]
	}

	actual, _, err := goCover(options)
	assert.Error(t, err)
	assert.Nil(t, actual)
	assert.Equal(t, 2, len(commandRun), commandRun)
	assert.True(t, commandRun["test --covermode set --coverprofile"], commandRun)
	assert.True(t, commandRun["tool cover --html"], commandRun)
}

func TestGoCoverBrowser(t *testing.T) {
	fakeOutput := map[string][]string{
		"test --covermode set --coverprofile": {"ignored"},
		"tool cover --func":                   {"expected return value"},
		"tool cover --html":                   {"ignored"},
	}
	commandRun := map[string]bool{}
	options := newTestOptions()
	options.coverageHTML = htmlOpenInBrowser
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		// The random filename is always the last arg, so drop it.
		parts := args[0 : len(args)-1]
		key := strings.Join(parts, " ")
		commandRun[key] = true
		return fakeOutput[key], nil
	}

	actual, _, err := goCover(options)
	assert.Nil(t, err)
	assert.Equal(t, []string{"expected return value"}, actual)
	assert.Equal(t, 3, len(commandRun), commandRun)
	assert.True(t, commandRun["test --covermode set --coverprofile"], commandRun)
	assert.True(t, commandRun["tool cover --func"], commandRun)
	assert.True(t, commandRun["tool cover --html"], commandRun)
}

func TestGoCoverPathFailure(t *testing.T) {
	options := newTestOptions()
	options.coverageHTML = htmlShowPath
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		return nil, nil
	}
	options.readLineWithRetry = func(*os.File) (string, error) {
		return "", errors.New("readLineWithRetry failed")
	}

	_, path, err := goCover(options)
	assert.ErrorContains(t, err, "readLineWithRetry failed")
	assert.Nil(t, path)
}

func TestGoCoverPath(t *testing.T) {
	fakeOutput := map[string][]string{
		"test --covermode set --coverprofile": {"ignored"},
		"tool cover --func":                   {"expected return value"},
		"tool cover --html":                   {"ignored"},
	}
	commandRun := map[string]bool{}
	options := newTestOptions()
	options.coverageHTML = htmlShowPath
	options.captureOutput = func(command string, args ...string) ([]string, error) {
		// The random filename is always the last arg, so drop it.
		parts := args[0 : len(args)-1]
		key := strings.Join(parts, " ")
		commandRun[key] = true
		return fakeOutput[key], nil
	}
	options.readLineWithRetry = func(*os.File) (string, error) {
		return "this is the fake path", nil
	}

	_, path, err := goCover(options)
	assert.Nil(t, err)
	assert.Equal(t, []string{"this is the fake path"}, path)
	assert.Equal(t, 3, len(commandRun), commandRun)
	assert.True(t, commandRun["test --covermode set --coverprofile"], commandRun)
	assert.True(t, commandRun["tool cover --func"], commandRun)
	assert.True(t, commandRun["tool cover --html"], commandRun)
}

func TestGoCoverCaptureFailure(t *testing.T) {
	options := newTestOptions()
	options.captureOutput = func(string, ...string) ([]string, error) {
		return []string{"this should not be seen"}, errors.New("error for testing")
	}
	actual, _, err := goCover(options)
	assert.Nil(t, actual)
	assert.ErrorContains(t, err, "error for testing")
}

func TestGoCoverCreateTempFailure(t *testing.T) {
	options := newTestOptions()
	options.createTemp = func(string, string) (*os.File, error) {
		return nil, errors.New("error for testing")
	}
	actual, _, err := goCover(options)
	assert.Nil(t, actual)
	assert.ErrorContains(t, err, "error for testing")
}

func validCoverageOutput() []string {
	coverage := `
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:26:		String			100.0%
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:48:		String			31.0%
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:53:		makeExampleConfig	50.0%
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:95:		parseYAMLConfig		100.0%
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:118:	realMain		17.3%
github.com/tobinjt/golang-coverage-check/golang-coverage-check.go:140:	main			0.0%
total:											(statements)		38.1%
`
	return strings.Split(coverage, "\n")
}

func TestParseCoverageOutputSuccess(t *testing.T) {
	options := newTestOptions()
	options.modulePath = "github.com/tobinjt/golang-coverage-check/"
	results, err := parseCoverageOutput(options, validCoverageOutput())
	assert.Nil(t, err)
	assert.Equal(t, 6, len(results))

	expected := []CoverageLine{
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "26",
			Function:   "String",
			Coverage:   100.0,
		},
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "48",
			Function:   "String",
			Coverage:   31.0,
		},
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "53",
			Function:   "makeExampleConfig",
			Coverage:   50.0,
		},
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "95",
			Function:   "parseYAMLConfig",
			Coverage:   100.0,
		},
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "118",
			Function:   "realMain",
			Coverage:   17.3,
		},
		{
			Filename:   "golang-coverage-check.go",
			LineNumber: "140",
			Function:   "main",
			Coverage:   0.0,
		},
	}
	assert.Equal(t, expected, results)
}

func TestParseCoverageOutputFailure(t *testing.T) {
	options := newTestOptions()

	badInputLine := `
github.com/.../golang-coverage-check.go:26:		String			100.0%
asdf
github.com/.../golang-coverage-check.go:140:	main			0.0%
total:											(statements)		38.1%
`
	_, err := parseCoverageOutput(options, strings.Split(badInputLine, "\n"))
	assert.ErrorContains(t, err, "expected 3 parts, found 1")

	badInputLine = `missing-line-number:		String			100.0%`
	_, err = parseCoverageOutput(options, []string{badInputLine})
	assert.ErrorContains(t, err, "expected `filename:linenumber:` in \"missing-line-number:\"")

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
		assert.ErrorContains(t, err, test.err)
	}
}

func stripComments(input []string) []string {
	output := []string{}
	for _, line := range input {
		if !strings.HasPrefix(line, "//") {
			output = append(output, line)
		}
	}
	return output
}

func TestCheckCoverage(t *testing.T) {
	tests := []struct {
		desc     string
		config   Config
		fInfoMap FunctionInfoMap
		input    []string
		errors   []string
		debug    []string
	}{

		{
			desc: "Filename matching",
			config: Config{
				Rules: []Rule{
					{
						FilenameRegex: "^utils.go$",
						Coverage:      100,
					},
				},
			},
			input: []string{
				"// Matches, insufficient coverage.",
				"utils.go:1:	ReadFileOrDie	57.0%",
				"// Matches, sufficient coverage.",
				"utils.go:2:	ParseIntOrDie	100.0%",
				"// Doesn't match, falls through to default.",
				"main.go:1:	main	22.0%",
			},
			errors: []string{
				"utils.go:1:\tReadFileOrDie\t57.0%: actual coverage 57.0% < required coverage 100.0%: matching rule",
				"matching rule is `FilenameRegex: ^utils.go$ FunctionRegex:  ReceiverRegex:  Coverage: 100 Comment: `",
			},
			debug: []string{
				// First coverage line.
				"Debug info for coverage matching",
				"Line utils.go:1:\tReadFileOrDie\t57.0%\n",
				"Matching rule: FilenameRegex: ^utils.go$ FunctionRegex:  ReceiverRegex:  Coverage: 100",
				"actual coverage 57.0% < required coverage 100.0%",
				// Second coverage line.
				"Line utils.go:2:\tParseIntOrDie\t100.0%",
				"Matching rule: FilenameRegex: ^utils.go$ FunctionRegex:  ReceiverRegex:  Coverage: 100 Comment:",
				"actual coverage 100.0% >= required coverage 100.0%",
				// Third coverage line.
				"Line main.go:1:\tmain\t22.0%",
				"Default coverage 0.0% satisfied",
			},
		},

		{
			desc: "Function matching",
			config: Config{
				Rules: []Rule{
					{
						FunctionRegex: "OrDie$",
						Coverage:      100,
					},
				},
			},
			input: []string{
				"// Matches, insufficient coverage.",
				"utils.go:1:	ReadFileOrDie	57.0%",
				"// Matches, sufficient coverage.",
				"utils.go:2:	ParseIntOrDie	100.0%",
				"// Doesn't match, falls through to default.",
				"main.go:1:	main	100.0%",
			},
			errors: []string{
				"utils.go:1:\tReadFileOrDie\t57.0%: actual coverage 57.0% < required coverage 100.0%: matching rule",
				"matching rule is `FilenameRegex:  FunctionRegex: OrDie$ ReceiverRegex:  Coverage: 100 Comment: `",
			},
			debug: []string{
				// First coverage line.
				"Debug info for coverage matching",
				"Line utils.go:1:\tReadFileOrDie\t57.0%\n",
				"Matching rule: FilenameRegex:  FunctionRegex: OrDie$ ReceiverRegex:  Coverage: 100",
				"actual coverage 57.0% < required coverage 100.0%",
				// Second coverage line.
				"Line utils.go:2:\tParseIntOrDie\t100.0%",
				"Matching rule: FilenameRegex:  FunctionRegex: OrDie$ ReceiverRegex:  Coverage: 100 Comment:",
				"actual coverage 100.0% >= required coverage 100.0%",
				// Third coverage line.
				"Line main.go:1:\tmain\t100.0%",
				"Default coverage 0.0% satisfied",
			},
		},

		{
			desc: "Receiver matching",
			config: Config{
				Rules: []Rule{
					{
						ReceiverRegex: "^testReceiver$",
						Coverage:      100,
					},
				},
			},
			input: []string{
				"// Matches, insufficient coverage.",
				"utils.go:1:	Commit	57.0%",
				"// Matches, sufficient coverage.",
				"utils.go:2:	String	100.0%",
				"// Doesn't match, falls through to default.",
				"main.go:1:	main	100.0%",
			},
			fInfoMap: FunctionInfoMap{
				"utils.go:1": {
					Filename:   "utils.go",
					LineNumber: "1",
					Function:   "Commit",
					Receiver:   "testReceiver",
				},
				"utils.go:2": {
					Filename:   "utils.go",
					LineNumber: "2",
					Function:   "String",
					Receiver:   "testReceiver",
				},
			},
			errors: []string{
				"utils.go:1:\tCommit\t57.0%: actual coverage 57.0% < required coverage 100.0%: matching rule",
				"matching rule is `FilenameRegex:  FunctionRegex:  ReceiverRegex: ^testReceiver$ Coverage: 100 Comment: `",
			},
			debug: []string{
				// First coverage line.
				"Debug info for coverage matching",
				"Line utils.go:1:\tCommit\t57.0%\n",
				"Matching rule: FilenameRegex:  FunctionRegex:  ReceiverRegex: ^testReceiver$ Coverage: 100",
				"actual coverage 57.0% < required coverage 100.0%",
				// Second coverage line.
				"Line utils.go:2:\tString\t100.0%",
				"Matching rule: FilenameRegex:  FunctionRegex:  ReceiverRegex: ^testReceiver$ Coverage: 100",
				"actual coverage 100.0% >= required coverage 100.0%",
				// Third coverage line.
				"Line main.go:1:\tmain\t100.0%",
				"Default coverage 0.0% satisfied",
			},
		},

		{
			desc: "Filename, Function, and Receiver matching",
			config: Config{
				Rules: []Rule{
					{
						FilenameRegex: "^utils.go$",
						FunctionRegex: "^Commit$",
						ReceiverRegex: "^testReceiver$",
						Coverage:      100,
					},
					{
						FilenameRegex: "^utils.go$",
						FunctionRegex: "^String$",
						ReceiverRegex: "^testReceiver$",
						Coverage:      100,
					},
				},
			},
			input: []string{
				"// Matches, insufficient coverage.",
				"utils.go:1:	Commit	57.0%",
				"// Matches, sufficient coverage.",
				"utils.go:2:	String	100.0%",
				"// Doesn't match, falls through to default.",
				"main.go:1:	main	100.0%",
			},
			fInfoMap: FunctionInfoMap{
				"utils.go:1": {
					Filename:   "utils.go",
					LineNumber: "1",
					Function:   "Commit",
					Receiver:   "testReceiver",
				},
				"utils.go:2": {
					Filename:   "utils.go",
					LineNumber: "2",
					Function:   "String",
					Receiver:   "testReceiver",
				},
			},
			errors: []string{
				"utils.go:1:\tCommit\t57.0%: actual coverage 57.0% < required coverage 100.0%: matching rule",
				"matching rule is `FilenameRegex: ^utils.go$ FunctionRegex: ^Commit$ ReceiverRegex: ^testReceiver$ Coverage: 100",
			},
			debug: []string{
				// First coverage line.
				"Debug info for coverage matching",
				"Line utils.go:1:\tCommit\t57.0%\n",
				"Matching rule: FilenameRegex: ^utils.go$ FunctionRegex: ^Commit$ ReceiverRegex: ^testReceiver$ Coverage: 100",
				"actual coverage 57.0% < required coverage 100.0%",
				// Second coverage line.
				"Line utils.go:2:\tString\t100.0%",
				"Matching rule: FilenameRegex: ^utils.go$ FunctionRegex: ^String$ ReceiverRegex: ^testReceiver$ Coverage: 100",
				"actual coverage 100.0% >= required coverage 100.0%",
				// Third coverage line.
				"Line main.go:1:\tmain\t100.0%",
				"Default coverage 0.0% satisfied",
			},
		},

		{
			desc: "Default coverage",
			config: Config{
				DefaultCoverage: 90,
			},
			input: []string{
				"// Insufficient coverage.",
				"utils.go:1:	ReadFileOrDie	57.0%",
				"// Sufficient coverage.",
				"utils.go:2:	ParseIntOrDie	100.0%",
			},
			errors: []string{
				"utils.go:1:\tReadFileOrDie\t57.0%: actual coverage 57.0% < default coverage 90.0%",
			},
			debug: []string{
				// First coverage line.
				"Debug info for coverage matching",
				"Line utils.go:1:\tReadFileOrDie\t57.0%\n",
				"Default coverage 90.0% not satisfied",
				// Second coverage line.
				"Line utils.go:2:\tParseIntOrDie\t100.0%",
				"Default coverage 90.0% satisfied",
			},
		},

		{
			desc: "No errors",
			config: Config{
				DefaultCoverage: 90,
			},
			input: []string{
				"// Sufficient coverage.",
				"utils.go:2:	ParseIntOrDie	100.0%",
			},
			errors: []string{},
			debug: []string{
				// First coverage line.
				"Line utils.go:2:\tParseIntOrDie\t100.0%",
				"Default coverage 90.0% satisfied",
			},
		},
	}

	options := newTestOptions()
	for _, test := range tests {
		coverage, err := parseCoverageOutput(options, stripComments(test.input))
		assert.Nil(t, err)
		config, err := validateConfig(test.config)
		assert.Nil(t, err)

		debug, err := checkCoverage(config, coverage, test.fInfoMap)
		if len(test.errors) == 0 {
			assert.Nil(t, err)
		} else {
			for i := range test.errors {
				assert.ErrorContains(t, err, test.errors[i], "err: "+test.desc)
			}
		}
		debugStr := strings.Join(debug, "\n")
		for i := range test.debug {
			assert.Contains(t, debugStr, test.debug[i], "debug: "+test.desc)
		}
	}
}

func TestValidateFlags(t *testing.T) {
	table := []struct {
		desc string
		err  string
		mod  func(opts Options) Options
	}{
		{
			desc: "good arguments",
			err:  "",
			mod: func(opts Options) Options {
				return opts
			},
		},
		{
			desc: "bad argument to --coverage_html",
			err:  "unrecognised option for flag --coverage_html: \"rejected\"; valid options are an empty string, \"browser\", or \"path\"",
			mod: func(opts Options) Options {
				opts.coverageHTML = "rejected"
				return opts
			},
		},
		{
			desc: "unexpected arguments",
			err:  "unexpected arguments",
			mod: func(opts Options) Options {
				opts.parsedArgs = []string{"asdf", "1234"}
				return opts
			},
		},
		{
			desc: "enabling multiple boolean flags",
			err:  "only one of --example_config, --generate_config",
			mod: func(opts Options) Options {
				opts.outputExampleConfig = true
				opts.coverageHTML = htmlShowPath
				opts.debugMatching = true
				return opts
			},
		},
	}

	for _, test := range table {
		options := test.mod(newTestOptions())
		err := validateFlags(options)
		if len(test.err) == 0 {
			assert.Nil(t, err, "err is nil check for "+test.desc)
		} else {
			assert.ErrorContains(t, err, test.err, "err contents check for "+test.desc)
		}
	}
}

func TestSetupFlagsAndUsage(t *testing.T) {
	options := newTestOptions()
	buffer := new(bytes.Buffer)
	options.flagOutput = buffer
	flags := setupFlagsAndUsage(&options)
	flags.Usage()
	message := buffer.String()
	assert.Contains(t, message,
		"Only one of --example_config, --generate_config, --debug_matching")
	assert.Contains(t, message, "set to \"path\" to output the path to the HTML")
}

func TestRealMain(t *testing.T) {
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
				opts.rawArgs = append(opts.rawArgs, "--example_config")
				return opts
			},
		},
		{
			desc:   "generateConfig",
			err:    "",
			output: "Generated rule for parseYAMLConfig",
			mod: func(opts Options) Options {
				opts.rawArgs = []string{"--generate_config"}
				opts.captureOutput = func(string, ...string) ([]string, error) {
					return validCoverageOutput(), nil
				}
				return opts
			},
		},
		{
			desc:   "unsupported flag",
			err:    "flag provided but not defined: -bad-flag",
			output: "",
			mod: func(opts Options) Options {
				opts.rawArgs = []string{"--bad-flag"}
				opts.flagOutput = new(bytes.Buffer)
				return opts
			},
		},
		{
			desc:   "unexpected arguments",
			err:    "unexpected arguments",
			output: "",
			mod: func(opts Options) Options {
				opts.rawArgs = []string{"asdf", "1234"}
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
			desc:   "building function info map fails",
			err:    "failed parsing code: open /does-not-exist: no such file or directory",
			output: "",
			mod: func(opts Options) Options {
				opts.dirToParse = "/does-not-exist"
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
		// Note that from here on the failures are that coverage isn't high enough.
		{
			desc:   "checkCoverage",
			err:    "golang-coverage-check.go:48:\tString\t31.0%: actual coverage 31.0% < default coverage 100.0%",
			output: "",
			mod: func(opts Options) Options {
				opts.captureOutput = func(string, ...string) ([]string, error) {
					return validCoverageOutput(), nil
				}
				return opts
			},
		},
		{
			desc:   "checkCoverage, with debugging output",
			err:    "golang-coverage-check.go:48:\tString\t31.0%: actual coverage 31.0% < default coverage 100.0",
			output: "Debug info for coverage matching",
			mod: func(opts Options) Options {
				opts.rawArgs = append(opts.rawArgs, "--debug_matching")
				opts.captureOutput = func(string, ...string) ([]string, error) {
					return validCoverageOutput(), nil
				}
				return opts
			},
		},
	}

	for _, test := range table {
		options := test.mod(newTestOptions())
		stdout, stderr, err := realMain(options)
		// Currently nothing is sent directly to stderr, all errors go through err.
		assert.Empty(t, stderr)
		if len(test.err) == 0 {
			assert.Nil(t, err, "err is nil check for "+test.desc)
		} else {
			assert.ErrorContains(t, err, test.err, "err contents check for "+test.desc)
		}
		if len(test.output) > 0 {
			assert.Contains(t, strings.Join(stdout, "\n"), test.output, "stdout contents check for "+test.desc)
		} else {
			assert.Nil(t, stdout, "stdout is nil check for "+test.desc)
		}
	}
}

func TestRunAndPrint(t *testing.T) {
	tests := []struct {
		desc   string
		stdout []string
		stderr []string
		err    error
	}{
		{
			desc:   "stdout only",
			stdout: []string{"this is going to stdout"},
		},
		{
			desc:   "stderr only",
			stderr: []string{"this is going to stderr"},
		},
		{
			desc: "there was an error",
			err:  errors.New("error for testing"),
		},
		{
			desc:   "all three",
			stdout: []string{"written to stdout"},
			stderr: []string{"written to stderr"},
			err:    errors.New("also an error"),
		},
	}

	for _, test := range tests {
		options := newTestOptions()
		stdout := new(bytes.Buffer)
		stderr := new(bytes.Buffer)
		options.stdout = stdout
		options.stderr = stderr

		exitCalledWith := -1
		options.exit = func(status int) {
			exitCalledWith = status
		}
		runMe := func(options Options) ([]string, []string, error) {
			return test.stdout, test.stderr, test.err
		}

		runAndPrint(options, runMe)
		if test.stderr != nil || test.err != nil {
			assert.Equal(t, 1, exitCalledWith)
			if test.stderr != nil {
				assert.Contains(t, stderr.String(), test.stderr[0])
			}
			if test.err != nil {
				assert.Contains(t, stderr.String(), test.err.Error())
			}
		} else {
			assert.Equal(t, 0, exitCalledWith)
			assert.Empty(t, stderr.String())
		}
		if test.stdout != nil {
			assert.Contains(t, stdout.String(), test.stdout[0])
		} else {
			assert.Empty(t, stdout.String())
		}
	}
}
