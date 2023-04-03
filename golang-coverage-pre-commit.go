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
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v2"
)

// Constants used with --coverage_html.
const htmlOpenInBrowser = "browser"
const htmlShowPath = "path"

// Used when sleeping between reads.
const sleepTime = 10 * time.Millisecond

// Options contains all the flags and dependency-injected functions used in
// this program.  It exists so that tests can easily replace flags and
// functions to trigger failure handling.
type Options struct {
	// Function pointers for dependency injection.
	// Used by goCover to run binaries and capture their stdout.
	captureOutput func(string, ...string) ([]string, error)
	// Makes the shell script used by --coverage_html=path executable.
	chmod func(*os.File, os.FileMode) error
	// Used to create a temporary file.
	createTemp func(string, string) (*os.File, error)
	// Called when exiting on error.
	exit func(int)
	// Reads a line from the output file created by --coverage_html=path,
	// retrying on EOF.
	readLineWithRetry func(*os.File) (string, error)
	// Used to set $BROWSER in goCoverCapturePath.
	setenv func(string, string) error

	// Paths to read from.
	// The config file to read, .golang-coverage-check.yaml except when
	// testing error handling.
	configFile string
	// The file to read module metadata from, "go.mod" except when testing error
	// handling.
	goMod string
	// The directory makeFunctionInfoMap() parses, "." except when testing error
	// handling.
	dirToParse string

	// Flags.
	// Set by --example_config; output an example config and exit.
	outputExampleConfig bool
	// Set by --generate_config; generate a config that exactly matches current
	// coverage.
	generateConfig bool
	// Set by --debug_matching; output debugging information about matching
	// coverage lines to rules.
	debugMatching bool
	// Set by --coverage_html; if non-empty, generate HTML output, either opening
	// a browser or outputting the path to the generated HTML.
	coverageHTML string

	// Other configuration/data that needs to be passed around.
	// Module path extracted from go.mod.
	modulePath string
	// Program name from os.Args.
	programName string
	// Command line arguments before parsing, doesn't include the program name.
	rawArgs []string
	// Command line arguments after parsing.
	parsedArgs []string
	// Where to write flag parsing error messages to; nil default means os.Stderr.
	flagOutput io.Writer
	// Where to write output and error messages.
	stdout io.Writer
	stderr io.Writer
}

// newOptions returns an Options struct with fields set to standard values.
func newOptions() Options {
	args := []string{}
	for i := range os.Args {
		if i > 0 {
			args = append(args, os.Args[i])
		}
	}
	return Options{
		captureOutput:     captureOutput,
		chmod:             chmod,
		createTemp:        os.CreateTemp,
		exit:              os.Exit,
		readLineWithRetry: readLineWithRetry,
		setenv:            os.Setenv,
		configFile:        ".golang-coverage-check.yaml",
		goMod:             "go.mod",
		dirToParse:        ".",
		programName:       os.Args[0],
		rawArgs:           args,
		stdout:            os.Stdout,
		stderr:            os.Stderr,
	}
}

// chmod is a wrapper around os.File.Chmod for easy testing.
func chmod(file *os.File, mode os.FileMode) error {
	return file.Chmod(mode)
}

// CoverageLine represents a single line of coverage output.
type CoverageLine struct {
	// Filename is the name of the source file, with the module path removed.
	Filename string
	// LineNumber is the line number the function can be found at.
	LineNumber string
	// Function is the name of the function.
	Function string
	// Coverage is the coverage percentage.
	Coverage float64
}

func (coverage CoverageLine) String() string {
	return fmt.Sprintf("%s:%s:\t%s\t%.1f%%",
		coverage.Filename, coverage.LineNumber, coverage.Function, coverage.Coverage)
}

// Rule represents a coverage rule.
type Rule struct {
	// Comment is not interpreted or used; it is provided as a structured way of
	// adding comments to an entry, so that automated editing is easier.
	Comment string
	// Regex used when matching against a filename.
	FilenameRegex string `yaml:"filename_regex"`
	// Regex used when matching against a function.
	FunctionRegex string `yaml:"function_regex"`
	// Regex used when matching against a method receiver.
	ReceiverRegex string `yaml:"receiver_regex"`
	// Coverage level required for this function or filename; this is a floating
	// point percentage, so it should be >= 0 and <= 100.
	Coverage float64
	// compiledFilenameRegex is the result of regexp.MustCompile(FilenameRegex).
	compiledFilenameRegex *regexp.Regexp
	// compiledFunctionRegex is the result of regexp.MustCompile(FunctionRegex).
	compiledFunctionRegex *regexp.Regexp
	// compiledFunctionRegex is the result of regexp.MustCompile(ReceiverRegex).
	compiledReceiverRegex *regexp.Regexp
}

func (rule Rule) String() string {
	return fmt.Sprintf("FilenameRegex: %v FunctionRegex: %v ReceiverRegex: %v Coverage: %v Comment: %v",
		rule.FilenameRegex, rule.FunctionRegex, rule.ReceiverRegex, rule.Coverage, rule.Comment)
}

// Config represents an entire user config loaded from .golang-coverage-check.yaml.
type Config struct {
	// Comment is not interpreted or used; it is provided as a structured way of
	// adding comments to a config, so that automated editing is easier.
	Comment string
	// DefaultCoverage is the default coverage required if none of the function or
	// filename rules match; this is a floating point percentage, so it should be
	// >= 0 and <= 100.
	DefaultCoverage float64 `yaml:"default_coverage"`
	// Rules is a list of rules that will be checked in-order, and the first match wins.
	Rules []Rule
}

func (config Config) String() string {
	bytes, _ := yaml.Marshal(&config)
	return string(bytes)
}

// makeExampleConfig creates an example Config and returns the string
// representation in YAML format.
func makeExampleConfig() []string {
	config := Config{
		Comment: "Comment is not interpreted or used; it is provided as a " +
			"structured way of adding comments to a config, so that automated " +
			"editing is easier.",
		DefaultCoverage: 80.0,
		Rules: []Rule{
			{
				Comment:       "Low coverage is acceptable for main()",
				FunctionRegex: "^main$",
				Coverage:      50,
			},
			{
				Comment: "All the fooOrDie() functions should be fully tested because" +
					" they panic() on failure",
				FunctionRegex: "OrDie$",
				Coverage:      100,
			},
			{
				Comment:       "Improve test coverage for parse_json.go?",
				FilenameRegex: "^parse_json.go$",
				Coverage:      73,
			},
			{
				Comment:       "Full coverage for other parsers",
				FilenameRegex: "^parse.*.go$",
				Coverage:      100,
			},
			{
				Comment:       "Url.String() has low coverage",
				FilenameRegex: "^urls.go$",
				FunctionRegex: "^String$",
				ReceiverRegex: "^Url$",
				Coverage:      56,
			},
			{
				Comment:       "String() everywhere else should have high coverage",
				FunctionRegex: "^String$",
				Coverage:      100,
			},
		},
	}
	return []string{config.String()}
}

// Generate a Config from coverage information; used by --generate_config.
func generateConfig(coverage []CoverageLine, fInfoMap FunctionInfoMap) Config {
	config := Config{
		DefaultCoverage: 100,
	}
	for _, cov := range coverage {
		key := functionLocationKey(cov.Filename, cov.LineNumber)
		receiver := fInfoMap[key].Receiver
		config.Rules = append(config.Rules,
			Rule{
				Comment:       "Generated rule for " + cov.Function + ", found at " + cov.Filename + ":" + cov.LineNumber,
				Coverage:      cov.Coverage,
				FunctionRegex: "^" + cov.Function + "$",
				FilenameRegex: "^" + cov.Filename + "$",
				ReceiverRegex: "^" + receiver + "$",
			})
	}
	return config
}

// validateConfig checks a config for correctness, including compiling every
// regex and caching the result.  Returns an updated config and an error.
func validateConfig(config Config) (Config, error) {
	if config.DefaultCoverage < 0 || config.DefaultCoverage > 100 {
		return config, fmt.Errorf("default coverage (%.1f) is outside the range 0-100", config.DefaultCoverage)
	}
	for i := range config.Rules {
		if config.Rules[i].FilenameRegex == "" && config.Rules[i].FunctionRegex == "" && config.Rules[i].ReceiverRegex == "" {
			return config, fmt.Errorf("every regex is an empty string in rule %v", config.Rules[i])
		}
		config.Rules[i].compiledFilenameRegex = regexp.MustCompile(config.Rules[i].FilenameRegex)
		config.Rules[i].compiledFunctionRegex = regexp.MustCompile(config.Rules[i].FunctionRegex)
		config.Rules[i].compiledReceiverRegex = regexp.MustCompile(config.Rules[i].ReceiverRegex)
		if config.Rules[i].Coverage < 0 || config.Rules[i].Coverage > 100 {
			return config, fmt.Errorf("coverage (%.1f) is outside the range 0-100 in %v", config.Rules[i].Coverage, config.Rules[i])
		}
	}
	return config, nil
}

// parseYAMLConfig parses raw YAML into a Config, checks it for correctness, and
// compiles every regex for speed.  Returns a config and an error.
func parseYAMLConfig(yamlConf []byte) (Config, error) {
	var config Config
	if err := yaml.UnmarshalStrict(yamlConf, &config); err != nil {
		return config, fmt.Errorf("failed parsing YAML: %w", err)
	}
	return validateConfig(config)
}

type FunctionInfo struct {
	// The filename the function is defined in.
	Filename string
	// The line number of the function definition.
	LineNumber string
	// The function name.
	Function string
	// For functions: empty string.  For methods: the receiver class.
	Receiver string
}

type FunctionInfoMap map[string]FunctionInfo

// functionLocationKey turns a filename and line number into a string key for
// a FunctionInfoMap; it must return the same key as FunctionInfo.key().
func functionLocationKey(filename, lineNumber string) string {
	return filename + ":" + lineNumber
}

// key generates a string key for a FunctionInfoMap; it must return the same
// key as functionLocationKey.
func (fl FunctionInfo) key() string {
	return fl.Filename + ":" + fl.LineNumber
}

// makeFunctionInfoMap parses the code in the current directory and constructs
// a map from filename:linenumber to FunctionInfo, returning a FunctionInfoMap
// and an error.
func makeFunctionInfoMap(opts Options) (FunctionInfoMap, error) {
	fmap := make(FunctionInfoMap)
	fset := token.NewFileSet()
	packageMap, err := parser.ParseDir(fset, opts.dirToParse, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, pkg := range packageMap {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				if function, ok := decl.(*ast.FuncDecl); ok {
					pos := fset.Position(function.Pos())
					fl := FunctionInfo{
						Filename:   pos.Filename,
						LineNumber: fmt.Sprintf("%d", pos.Line),
						Function:   function.Name.Name,
						Receiver:   "",
					}
					if function.Recv != nil {
						// This is ugly, but I haven't found a better way to get the string
						// out of the data structure.
						fl.Receiver = fmt.Sprintf("%v", function.Recv.List[0].Type)
					}
					fmap[fl.key()] = fl
				}
			}
		}
	}

	return fmap, nil
}

// captureOutput runs a command and returns the output on success (a slice of
// strings) and an error on failure.
func captureOutput(command string, args ...string) ([]string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed running `%s`: %w\n%s", cmd, err, output)
	}
	return strings.Split(string(output), "\n"), nil
}

// readLineWithRetry reads a single line from file, retrying on EOF and
// returning all other errors.
func readLineWithRetry(file *os.File) (string, error) {
	reader := bufio.NewReader(file)
	var line string
	var err error
	for {
		line, err = reader.ReadString('\n')
		if err == nil {
			break
		}
		if err == io.EOF {
			time.Sleep(sleepTime)
		} else {
			return "", err
		}
	}
	return line, nil
}

// goCoverCapturePath sets $BROWSER so the path to the generated coverage is
// captured and printed to the user.  Returns an array of strings (only one
// element) and an error on failure.
func goCoverCapturePath(options Options, coverageFile string) ([]string, error) {
	outputFile, err := options.createTemp("", "golang-coverage-check.*.html-path")
	if err != nil {
		return nil, err
	}
	defer os.Remove(outputFile.Name())
	shellScript, err := options.createTemp("", "golang-coverage-check.*.sh")
	if err != nil {
		return nil, err
	}
	defer os.Remove(shellScript.Name())

	shellScriptContents := `#!/bin/sh

echo "$@" > "%s"
`
	fmt.Fprintf(shellScript, shellScriptContents, outputFile.Name())
	if err = options.chmod(shellScript, 0755); err != nil {
		return nil, err
	}
	if err = options.setenv("BROWSER", shellScript.Name()); err != nil {
		return nil, err
	}
	_, err = options.captureOutput("go", "tool", "cover", "--html", coverageFile)
	if err != nil {
		return nil, err
	}
	htmlFile, err := options.readLineWithRetry(outputFile)
	if err != nil {
		return nil, err
	}
	return []string{htmlFile}, nil
}

// goCover runs the commands to generate coverage.  It returns
//   - a slice of strings containing the command's output
//   - a slice of strings containing the path to the generated HTML if
//     --coverage_html == htmlShowPath
//   - an error if running any command failed.
func goCover(options Options) ([]string, []string, error) {
	file, err := options.createTemp("", "golang-coverage-check")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(file.Name())

	_, err = options.captureOutput("go", "test", "--covermode", "set", "--coverprofile", file.Name())
	if err != nil {
		return nil, nil, err
	}

	if options.coverageHTML == htmlOpenInBrowser {
		_, err = options.captureOutput("go", "tool", "cover", "--html", file.Name())
		if err != nil {
			return nil, nil, err
		}
	}

	var htmlPath []string
	if options.coverageHTML == htmlShowPath {
		htmlPath, err = goCoverCapturePath(options, file.Name())
		if err != nil {
			return nil, nil, err
		}
	}

	lines, err := options.captureOutput("go", "tool", "cover", "--func", file.Name())
	return lines, htmlPath, err
}

// parseCoverageOutput parses all the coverage lines and turns each into a
// CoverageLine, returning a slice of CoverageLine and an error.
func parseCoverageOutput(options Options, output []string) ([]CoverageLine, error) {
	results := []CoverageLine{}
	lineSplitter := regexp.MustCompile(`\t+`)
	percentageExtractor := regexp.MustCompile(`^(.*)%$`)

	for i := range output {
		if len(output[i]) == 0 {
			// Skip blank lines.
			continue
		}
		parts := lineSplitter.Split(output[i], -1)
		if len(parts) != 3 {
			return nil, fmt.Errorf("expected 3 parts, found %v, in \"%v\" => %v", len(parts), output[i], parts)
		}
		if parts[0] == "total:" {
			continue
		}
		rawFilename, rawFunction, rawPercentage := parts[0], parts[1], parts[2]

		matches := percentageExtractor.FindStringSubmatch(rawPercentage)
		if len(matches) == 0 {
			return nil, fmt.Errorf("could not extract percentage from \"%v\"", rawPercentage)
		}
		percentage, err := strconv.ParseFloat(matches[1], 64)
		if err != nil {
			return nil, fmt.Errorf("failed parsing \"%v\" as a float: %w", rawPercentage, err)
		}
		if percentage > 100 {
			return nil, fmt.Errorf("percentage (%v) > 100 in \"%v\"", percentage, rawPercentage)
		}
		if percentage < 0 {
			return nil, fmt.Errorf("percentage (%v) < 0 in \"%v\"", percentage, rawPercentage)
		}

		fileLineParts := strings.Split(rawFilename, ":")
		if len(fileLineParts) != 3 {
			return nil, fmt.Errorf("expected `filename:linenumber:` in \"%v\"", rawFilename)
		}

		results = append(results, CoverageLine{
			Filename:   strings.TrimPrefix(fileLineParts[0], options.modulePath),
			LineNumber: fileLineParts[1],
			Function:   rawFunction,
			Coverage:   percentage,
		})
	}
	return results, nil
}

// checkCoverage checks that each function meets the required level of coverage,
// returning a string containing debugging information and an error if
// appropriate.
func checkCoverage(config Config, coverage []CoverageLine, fInfoMap FunctionInfoMap) ([]string, error) {
	errors := []string{}
	debugInfo := []string{"Debug info for coverage matching"}

Coverage:
	for _, cov := range coverage {
		debugInfo = append(debugInfo, fmt.Sprintf("- Line %v", cov))
		for _, rule := range config.Rules {
			if rule.FilenameRegex != "" && !rule.compiledFilenameRegex.MatchString(cov.Filename) {
				continue
			}
			if rule.FunctionRegex != "" && !rule.compiledFunctionRegex.MatchString(cov.Function) {
				continue
			}
			if rule.ReceiverRegex != "" {
				key := functionLocationKey(cov.Filename, cov.LineNumber)
				receiver := fInfoMap[key].Receiver
				if !rule.compiledReceiverRegex.MatchString(receiver) {
					continue
				}
			}
			debugInfo = append(debugInfo, fmt.Sprintf("  - Matching rule: %v", rule))
			if cov.Coverage < rule.Coverage {
				debugInfo = append(debugInfo,
					fmt.Sprintf("  - actual coverage %.1f%% < required coverage %.1f%%",
						cov.Coverage, rule.Coverage))
				errors = append(errors,
					fmt.Sprintf("%v: actual coverage %.1f%% < required coverage %.1f%%: matching rule is `%v`",
						cov, cov.Coverage, rule.Coverage, rule))
			} else {
				debugInfo = append(debugInfo,
					fmt.Sprintf("  - actual coverage %.1f%% >= required coverage %.1f%%",
						cov.Coverage, rule.Coverage))
			}
			continue Coverage
		}

		if cov.Coverage < config.DefaultCoverage {
			errors = append(errors,
				fmt.Sprintf("%v: actual coverage %.1f%% < default coverage %.1f%%",
					cov, cov.Coverage, config.DefaultCoverage))
			debugInfo = append(debugInfo,
				fmt.Sprintf("  - Default coverage %.1f%% not satisfied",
					config.DefaultCoverage))
		} else {
			debugInfo = append(debugInfo,
				fmt.Sprintf("  - Default coverage %.1f%% satisfied",
					config.DefaultCoverage))
		}
	}

	if len(errors) > 0 {
		return debugInfo, fmt.Errorf("%s", strings.Join(errors, "\n"))
	}
	return debugInfo, nil
}

// multipleBooleanFlagsMessage returns the message about accepting only one
// boolean flag, because it's used in multiple places.
func multipleBooleanFlagsMessage() string {
	return fmt.Sprintf(
		`only one of --example_config, --generate_config, --debug_matching, or
--coverage_html=%s can be used because they all output to stdout and their
output would be mixed up if more than one is used`, htmlShowPath)
}

// validateFlags checks for conflicting flags and returns an error.
func validateFlags(options Options) error {
	if len(options.parsedArgs) > 0 {
		return fmt.Errorf("unexpected arguments: %v", options.parsedArgs)
	}
	if options.coverageHTML != "" &&
		options.coverageHTML != htmlOpenInBrowser &&
		options.coverageHTML != htmlShowPath {
		return fmt.Errorf("unrecognised option for flag --coverage_html: %q; valid options are an empty string, %q, or %q",
			options.coverageHTML, htmlOpenInBrowser, htmlShowPath)
	}

	enabled := []bool{options.outputExampleConfig, options.generateConfig, options.debugMatching}
	enabled = append(enabled, options.coverageHTML == htmlShowPath)
	count := 0
	for _, e := range enabled {
		if e {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("%s", multipleBooleanFlagsMessage())
	}
	return nil
}

// setupFlagsAndUsage sets up all flags and the usage message.
func setupFlagsAndUsage(options *Options) *flag.FlagSet {
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.SetOutput(options.flagOutput)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage of %s:\n", options.programName)
		flags.PrintDefaults()
		message := []rune(multipleBooleanFlagsMessage())
		message[0] = unicode.ToUpper(message[0])
		fmt.Fprintf(flags.Output(), "\n%s.\n\n", string(message))
	}

	flags.BoolVar(&options.outputExampleConfig, "example_config", false,
		`Output an example config and exit without checking coverage`)
	flags.BoolVar(&options.generateConfig, "generate_config", false,
		`Output a config that exactly matches current coverage and exit
without checking coverage`)
	flags.BoolVar(&options.debugMatching, "debug_matching", false,
		`Output debugging information about matching coverage lines to rules`)
	flags.StringVar(&options.coverageHTML, "coverage_html", "",
		fmt.Sprintf(
			`If non-empty will generate HTML coverage:
- set to %q to open in a browser
- set to %q to output the path to the HTML

In both cases coverage will still be checked against the rules
you've defined.  Note that %q has only been tested on MacOS,
and requires /bin/sh, so it definitely won't work on Windows.
`,
			htmlOpenInBrowser, htmlShowPath, htmlShowPath))
	return flags
}

// realMain contains all the high level logic for the application, but in a
// testable function.  It takes Options created by newOptions(), returns a
// slice of strings to be output to stdout, a slice of strings to be output to
// stderr, and an error if anything failed.
func realMain(options Options) ([]string, []string, error) {
	flags := setupFlagsAndUsage(&options)
	if err := flags.Parse(options.rawArgs); err != nil {
		return nil, nil, err
	}
	options.parsedArgs = flags.Args()

	if err := validateFlags(options); err != nil {
		return nil, nil, err
	}

	if options.outputExampleConfig {
		return makeExampleConfig(), nil, nil
	}

	modBytes, err := os.ReadFile(options.goMod)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading %v: %w", options.goMod, err)
	}
	options.modulePath = modfile.ModulePath(modBytes) + "/"

	if options.generateConfig {
		// Don't require an existing config when generating one.
		options.configFile = os.DevNull
	}
	configBytes, err := os.ReadFile(options.configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading config %v: %w", options.configFile, err)
	}
	config, err := parseYAMLConfig(configBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing config %v: %w", options.configFile, err)
	}

	fInfoMap, err := makeFunctionInfoMap(options)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing code: %w", err)
	}

	rawCoverage, htmlPath, err := goCover(options)
	if err != nil {
		return nil, nil, err
	}
	parsedCoverage, err := parseCoverageOutput(options, rawCoverage)
	if err != nil {
		return nil, nil, err
	}

	if options.generateConfig {
		newConfig := generateConfig(parsedCoverage, fInfoMap)
		return []string{newConfig.String()}, nil, nil
	}

	debugInfo, err := checkCoverage(config, parsedCoverage, fInfoMap)
	if options.debugMatching {
		return debugInfo, nil, err
	}
	return htmlPath, nil, err
}

// runAndPrint takes Options and a function to run, runs the function, prints
// the output string returned by the function, and if the function returns an
// error prints the error and exits unsuccessfully.
func runAndPrint(options Options, runMe func(options Options) ([]string, []string, error)) {
	stdout, stderr, err := runMe(options)
	exitStatus := 0
	if len(stdout) > 0 {
		fmt.Fprint(options.stdout, strings.Join(stdout, "\n"))
	}
	if len(stderr) > 0 {
		fmt.Fprint(options.stderr, strings.Join(stderr, "\n"))
		exitStatus = 1
	}
	if err != nil {
		fmt.Fprintf(options.stderr, "%v: %v\n", options.programName, err)
		exitStatus = 1
	}
	options.exit(exitStatus)
}

func main() {
	runAndPrint(newOptions(), realMain)
}
