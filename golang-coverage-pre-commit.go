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

	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v2"
)

const htmlOpenInBrowser = "browser"
const htmlShowPath = "path"

// Options contains all the flags and dependency-injected functions used in
// this program.  It exists so that tests can easily replace flags and
// functions to trigger failure handling.
type Options struct {
	// Function pointers for dependency injection.
	// Used by goCover to run binaries and capture their stdout.
	captureOutput func(string, ...string) ([]string, error)
	// Used to create a temporary file.
	createTemp func(string, string) (*os.File, error)
	// Paths to read from.
	// The config file to read.
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
	// Set by --generate_config; generate a config that exactly matches current coverage.
	generateConfig bool
	// Set by --debug_matching; output debugging information about matching
	// coverage lines to rules.
	debugMatching bool
	// Set by --coverage_html; if non-empty, generate HTML output, either opening
	// a browser or outputting the path to the generated HTML.
	htmlOutput string

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
	// Called when existing on error.
	exit func(int)
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
		captureOutput: captureOutput,
		createTemp:    os.CreateTemp,
		configFile:    ".golang-coverage-pre-commit.yaml",
		goMod:         "go.mod",
		dirToParse:    ".",
		programName:   os.Args[0],
		rawArgs:       args,
		stdout:        os.Stdout,
		stderr:        os.Stderr,
		exit:          os.Exit,
	}
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
	return fmt.Sprintf("%s:%s:\t%s\t%.1f%%", coverage.Filename, coverage.LineNumber, coverage.Function, coverage.Coverage)
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

// Config represents an entire user config loaded from .golang-coverage-pre-commit.yaml.
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

// functionLocationKey turns a filename and linenumber into a string key for
// a FunctionInfoMap.
func functionLocationKey(filename, lineNumber string) string {
	return filename + ":" + lineNumber
}

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

// func goCoverCapturePath(options Options) ()

// goCover runs the commands to generate coverage.  It returns
//   - a slice of strings containing the command's output
//   - a slice of strings containing the path to the generated HTML if
//     --coverage_html == htmlShowPath
//   - an error if running any command failed.
func goCover(options Options) ([]string, []string, error) {
	file, err := options.createTemp("", "golang-coverage-pre-commit")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(file.Name())

	_, err = options.captureOutput("go", "test", "--covermode", "set", "--coverprofile", file.Name())
	if err != nil {
		return nil, nil, err
	}

	if options.htmlOutput == htmlOpenInBrowser {
		_, err = options.captureOutput("go", "tool", "cover", "--html", file.Name())
		if err != nil {
			return nil, nil, err
		}
	}

	if options.htmlOutput == htmlShowPath {
		// TODO: write a function to capture the path.
		return nil, nil, fmt.Errorf("not yet implemented: %q", htmlShowPath)
	}

	lines, err := options.captureOutput("go", "tool", "cover", "--func", file.Name())
	return lines, nil, err
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
				debugInfo = append(debugInfo, fmt.Sprintf("  - actual coverage %.1f%% < required coverage %.1f%%", cov.Coverage, rule.Coverage))
				errors = append(errors, fmt.Sprintf("%v: actual coverage %.1f%% < required coverage %.1f%%: matching rule is `%v`", cov, cov.Coverage, rule.Coverage, rule))
			} else {
				debugInfo = append(debugInfo, fmt.Sprintf("  - actual coverage %.1f%% >= required coverage %.1f%%", cov.Coverage, rule.Coverage))
			}
			continue Coverage
		}

		if cov.Coverage < config.DefaultCoverage {
			errors = append(errors, fmt.Sprintf("%v: actual coverage %.1f%% < default coverage %.1f%%", cov, cov.Coverage, config.DefaultCoverage))
			debugInfo = append(debugInfo, fmt.Sprintf("  - Default coverage %.1f%% not satisfied", config.DefaultCoverage))
		} else {
			debugInfo = append(debugInfo, fmt.Sprintf("  - Default coverage %.1f%% satisfied", config.DefaultCoverage))
		}
	}

	if len(errors) > 0 {
		return debugInfo, fmt.Errorf("%s", strings.Join(errors, "\n"))
	}
	return debugInfo, nil
}

// realMain contains all the high level logic for the application, but in a
// testable function.  It takes Options created by newOptions(), returns a
// slice of strings to be output to stdout, a slice of strings to be output to
// stderr, and an error if anything failed.
func realMain(options Options) ([]string, []string, error) {
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.SetOutput(options.flagOutput)
	flags.BoolVar(&options.outputExampleConfig, "example_config", false, "output an example config and exit without checking coverage")
	flags.BoolVar(&options.generateConfig, "generate_config", false, "output a config that exactly matches current coverage and exit without checking coverage")
	flags.BoolVar(&options.debugMatching, "debug_matching", false, "output debugging information about matching coverage lines to rules")
	flags.StringVar(&options.htmlOutput, "coverage_html", "",
		fmt.Sprintf("if non-empty will generate HTML coverage.  Set to %q to open in a browser; set to %q to output the path to the HTML; in both cases coverage will still be checked against the rules you've defined",
			htmlOpenInBrowser, htmlShowPath))

	if err := flags.Parse(options.rawArgs); err != nil {
		return nil, nil, err
	}
	options.parsedArgs = flags.Args()

	if len(options.parsedArgs) > 0 {
		return nil, nil, fmt.Errorf("unexpected arguments: %v", options.parsedArgs)
	}
	if options.htmlOutput != "" && options.htmlOutput != htmlOpenInBrowser && options.htmlOutput != htmlShowPath {
		return nil, nil, fmt.Errorf("unrecognised option for flag --coverage_html: %q; valid options are an empty string, %q, or %q",
			options.htmlOutput, htmlOpenInBrowser, htmlShowPath)
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

	rawCoverage, _, err := goCover(options)
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
	return nil, nil, err
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
