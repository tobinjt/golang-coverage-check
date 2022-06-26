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

// Options contains all the flags and dependency-injected functions used in
// this program.  It exists so that tests can easily replace flags and
// functions to trigger failure handling.
type Options struct {
	// Function pointers for dependency injection.
	// Used by goCover to run binaries and capture their stdout.
	captureOutput func(string, ...string) ([]string, error)
	// Used to create a temporary flie.
	createTemp func(string, string) (*os.File, error)
	// Paths to read from.
	// The config file to read.
	configFile string
	// The file to read module metadata from, "go.mod" except when testing error
	// handling.
	goMod string
	// The directory makeFunctionLocationMap() parses, "." except when testing error
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
	// Set by --browser; open coverage results in a browser.
	showCoverageInBrowser bool
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

// makeExampleConfig creates an example Config and returns the string representation.
func makeExampleConfig() string {
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
	return config.String()
}

// Generate a Config from coverage information; used by --generate_config.
func generateConfig(coverage []CoverageLine, functionLocationMap map[string]FunctionLocation) Config {
	config := Config{
		DefaultCoverage: 100,
	}
	for _, cov := range coverage {
		key := functionLocationKey(cov.Filename, cov.LineNumber)
		receiver := functionLocationMap[key].Receiver
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
// regex and caching the result.
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
// compiles every regex for speed.
func parseYAMLConfig(yamlConf []byte) (Config, error) {
	var config Config
	if err := yaml.UnmarshalStrict(yamlConf, &config); err != nil {
		return config, fmt.Errorf("failed parsing YAML: %w", err)
	}
	return validateConfig(config)
}

type FunctionLocation struct {
	// The filename the function is defined in.
	Filename string
	// The line number of the function definition.
	LineNumber string
	// The function name.
	Function string
	// For functions: empty string.  For methods: the receiver class.
	Receiver string
}

func functionLocationKey(filename, lineNumber string) string {
	return filename + ":" + lineNumber
}

func (fl FunctionLocation) key() string {
	return fl.Filename + ":" + fl.LineNumber
}

// makeFunctionLocationMap parses the code in the current directory and
// constructs a map from filename:linenumber to FunctionLocation.
func makeFunctionLocationMap(opts Options) (map[string]FunctionLocation, error) {
	fmap := make(map[string]FunctionLocation)
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
					fl := FunctionLocation{
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

// captureOutput runs a command and returns the output on success and an error
// on failure.
func captureOutput(command string, args ...string) ([]string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("failed running `%s`: %w\n%s", cmd, err, output)
	}
	return strings.Split(string(output), "\n"), nil
}

// goCover runs the commands to generate coverage and returns that output.
func goCover(options Options) ([]string, error) {
	file, err := options.createTemp("", "golang-coverage-pre-commit")
	if err != nil {
		return []string{}, err
	}
	defer os.Remove(file.Name())

	_, err = options.captureOutput("go", "test", "--covermode", "set", "--coverprofile", file.Name())
	if err != nil {
		return []string{}, err
	}

	if options.showCoverageInBrowser {
		_, err = options.captureOutput("go", "tool", "cover", "--html", file.Name())
		if err != nil {
			return []string{}, err
		}
	}

	return options.captureOutput("go", "tool", "cover", "--func", file.Name())
}

// parseCoverageOutput parses all the coverage lines and turns each into a
// CoverageLine.
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
			return []CoverageLine{}, fmt.Errorf("expected 3 parts, found %v, in \"%v\" => %v", len(parts), output[i], parts)
		}
		if parts[0] == "total:" {
			continue
		}
		rawFilename, rawFunction, rawPercentage := parts[0], parts[1], parts[2]

		matches := percentageExtractor.FindStringSubmatch(rawPercentage)
		if len(matches) == 0 {
			return []CoverageLine{}, fmt.Errorf("could not extract percentage from \"%v\"", rawPercentage)
		}
		percentage, err := strconv.ParseFloat(matches[1], 64)
		if err != nil {
			return []CoverageLine{}, fmt.Errorf("failed parsing \"%v\" as a float: %w", rawPercentage, err)
		}
		if percentage > 100 {
			return []CoverageLine{}, fmt.Errorf("percentage (%v) > 100 in \"%v\"", percentage, rawPercentage)
		}
		if percentage < 0 {
			return []CoverageLine{}, fmt.Errorf("percentage (%v) < 0 in \"%v\"", percentage, rawPercentage)
		}

		fileLineParts := strings.Split(rawFilename, ":")
		if len(fileLineParts) != 3 {
			return []CoverageLine{}, fmt.Errorf("expected `filename:linenumber:` in \"%v\"", rawFilename)
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
// returning debugging information and an error if appropriate.
func checkCoverage(config Config, coverage []CoverageLine, functionLocationMap map[string]FunctionLocation) (string, error) {
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
				receiver := functionLocationMap[key].Receiver
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

	// Ensure we have a trailing \n.
	debugInfo = append(debugInfo, "")
	debug := strings.Join(debugInfo, "\n")
	if len(errors) > 0 {
		return debug, fmt.Errorf("%s", strings.Join(errors, "\n"))
	}
	return debug, nil
}

func realMain(options Options) (string, error) {
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.SetOutput(options.flagOutput)
	flags.BoolVar(&options.outputExampleConfig, "example_config", false, "output an example config and exit")
	flags.BoolVar(&options.generateConfig, "generate_config", false, "output a config that exactly matches current coverage and exit")
	flags.BoolVar(&options.showCoverageInBrowser, "browser", false, "open coverage results in a browser")
	flags.BoolVar(&options.debugMatching, "debug_matching", false, "output debugging information about matching coverage lines to rules")
	if err := flags.Parse(options.rawArgs); err != nil {
		return "", err
	}
	options.parsedArgs = flags.Args()

	if len(options.parsedArgs) > 0 {
		return "", fmt.Errorf("unexpected arguments: %v", options.parsedArgs)
	}
	if options.outputExampleConfig {
		return makeExampleConfig(), nil
	}

	modBytes, err := os.ReadFile(options.goMod)
	if err != nil {
		return "", fmt.Errorf("failed reading %v: %w", options.goMod, err)
	}
	options.modulePath = modfile.ModulePath(modBytes) + "/"

	if options.generateConfig {
		// Don't require an existing config when generating one.
		options.configFile = os.DevNull
	}
	configBytes, err := os.ReadFile(options.configFile)
	if err != nil {
		return "", fmt.Errorf("failed reading config %v: %w", options.configFile, err)
	}
	config, err := parseYAMLConfig(configBytes)
	if err != nil {
		return "", fmt.Errorf("failed parsing config %v: %w", options.configFile, err)
	}

	functionLocationMap, err := makeFunctionLocationMap(options)
	if err != nil {
		return "", err
	}

	rawCoverage, err := goCover(options)
	if err != nil {
		return "", err
	}
	parsedCoverage, err := parseCoverageOutput(options, rawCoverage)
	if err != nil {
		return "", err
	}

	if options.generateConfig {
		newConfig := generateConfig(parsedCoverage, functionLocationMap)
		return newConfig.String(), nil
	}

	debugInfo, err := checkCoverage(config, parsedCoverage, functionLocationMap)
	if options.debugMatching {
		return debugInfo, err
	}
	return "", err
}

func runAndPrint(options Options, runMe func(options Options) (string, error)) {
	output, err := runMe(options)
	fmt.Fprint(options.stdout, output)
	if err != nil {
		fmt.Fprintf(options.stderr, "%v: %v\n", options.programName, err)
		options.exit(1)
	}
}

func main() {
	runAndPrint(newOptions(), realMain)
}
