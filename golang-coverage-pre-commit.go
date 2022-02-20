package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
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
	// Flags.
	// Set by --example_config; output an example config and exit.
	outputExampleConfig bool
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

// Rule represents a single function or filename rule.
type Rule struct {
	// Comment is not interpreted or used; it is provided as a structured way of
	// adding comments to an entry, so that automated editing is easier.
	Comment string
	// Regex used when matching against a function or filename.
	Regex string
	// Coverage level required for this function or filename; this is a floating
	// point percentage, so it should be >= 0 and <= 100.
	Coverage float64
	// compiledRegex is the result of regexp.MustCompile(Regex).
	compiledRegex *regexp.Regexp
}

func (rule Rule) String() string {
	return fmt.Sprintf("Regex: %v Coverage: %v Comment: %v", rule.Regex, rule.Coverage, rule.Comment)
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
	// Functions is a list of rules matching against *function names*; they will
	// be checked in-order, and the first match wins.
	Functions []Rule
	// Functions is a list of rules matching against *filenames*; they will be
	// checked in-order, and the first match wins.
	Filenames []Rule
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
		Functions: []Rule{
			{
				Comment:  "Low coverage is acceptable for main()",
				Regex:    "^main$",
				Coverage: 50,
			},
			{
				Comment: "All the fooOrDie() functions should be fully tested because" +
					" they panic() on failure",
				Regex:    "OrDie$",
				Coverage: 100,
			},
		},
		Filenames: []Rule{
			{
				Comment:  "TO" + "DO: improve test coverage for parse_json.go",
				Regex:    "^parse_json.go$",
				Coverage: 73,
			},
			{
				Comment:  "Full coverage for other parsers",
				Regex:    "^parse.*.go$",
				Coverage: 100,
			},
		},
	}
	return config.String()
}

// parseYAMLConfig parses raw YAML into a Config, checks it for correctness, and
// compiles every regex for speed.
func parseYAMLConfig(yamlConf []byte) (Config, error) {
	var config Config
	if err := yaml.Unmarshal(yamlConf, &config); err != nil {
		return config, fmt.Errorf("failed parsing YAML: %w", err)
	}
	if config.DefaultCoverage < 0 || config.DefaultCoverage > 100 {
		return config, fmt.Errorf("default coverage (%.1f) is outside the range 0-100", config.DefaultCoverage)
	}
	for i := range config.Functions {
		config.Functions[i].compiledRegex = regexp.MustCompile(config.Functions[i].Regex)
		if config.Functions[i].Coverage < 0 || config.Functions[i].Coverage > 100 {
			return config, fmt.Errorf("coverage (%.1f) is outside the range 0-100 in %v", config.Functions[i].Coverage, config.Functions[i])
		}
	}
	for i := range config.Filenames {
		config.Filenames[i].compiledRegex = regexp.MustCompile(config.Filenames[i].Regex)
		if config.Filenames[i].Coverage < 0 || config.Filenames[i].Coverage > 100 {
			return config, fmt.Errorf("coverage (%.1f) is outside the range 0-100 in %v", config.Filenames[i].Coverage, config.Filenames[i])
		}
	}
	return config, nil
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
func checkCoverage(config Config, coverage []CoverageLine) (string, error) {
	errors := []string{}
	debugInfo := []string{"Debug info for coverage matching"}

Coverage:
	for _, cov := range coverage {
		debugInfo = append(debugInfo, fmt.Sprintf("- Line %v", cov))
		for _, function := range config.Functions {
			if function.compiledRegex.MatchString(cov.Function) {
				debugInfo = append(debugInfo, fmt.Sprintf("  - Function match: %v", function))
				if cov.Coverage < function.Coverage {
					errors = append(errors, fmt.Sprintf("%v: coverage %.1f%% < %.1f%%: matching function rule is `%v`", cov, cov.Coverage, function.Coverage, function))
				}
				continue Coverage
			}
		}

		for _, filename := range config.Filenames {
			if filename.compiledRegex.MatchString(cov.Filename) {
				debugInfo = append(debugInfo, fmt.Sprintf("  - Filename match: %v", filename))
				if cov.Coverage < filename.Coverage {
					errors = append(errors, fmt.Sprintf("%v: coverage %.1f%% < %.1f%%: matching filename rule is `%v`", cov, cov.Coverage, filename.Coverage, filename))
				}
				continue Coverage
			}
		}

		if cov.Coverage < config.DefaultCoverage {
			errors = append(errors, fmt.Sprintf("%v: coverage %.1f%% < %.1f%%: default coverage requirement %.1f%%", cov, cov.Coverage, config.DefaultCoverage, config.DefaultCoverage))
			debugInfo = append(debugInfo, "  - Default coverage not satisfied")
		} else {
			debugInfo = append(debugInfo, "  - Default coverage satisfied")
		}
	}

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

	configBytes, err := os.ReadFile(options.configFile)
	if err != nil {
		return "", fmt.Errorf("failed reading config %v: %w", options.configFile, err)
	}
	config, err := parseYAMLConfig(configBytes)
	if err != nil {
		return "", fmt.Errorf("failed parsing config %v: %w", options.configFile, err)
	}

	rawCoverage, err := goCover(options)
	if err != nil {
		return "", err
	}
	parsedCoverage, err := parseCoverageOutput(options, rawCoverage)
	if err != nil {
		return "", err
	}

	debugInfo, err := checkCoverage(config, parsedCoverage)
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
