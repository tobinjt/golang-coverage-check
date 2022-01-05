package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

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
	bytes, _ := yaml.Marshal(&rule)
	return string(bytes)
}

// Config represents an entire user config.
type Config struct {
	// Comment is not interpreted or used; it is provided as a structured way of
	// adding comments to a config, so that automated editing is easier.
	Comment string
	// Default is the default coverage required if none of the function or
	// filename rules match; this is a floating point percentage, so it should be
	// >= 0 and <= 100.
	Default float64
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

func makeExampleConfig() string {
	config := Config{
		Comment: "Comment is not interpreted or used; it is provided as a " +
			"structured way of adding comments to a config, so that automated " +
			"editing is easier.",
		Default: 80.0,
		Functions: []Rule{
			{
				Comment:  "Low coverage is acceptable for main()",
				Regex:    "^main$",
				Coverage: 50,
			},
			{
				Comment: "All the fooOrDie() functions should be fully tested because" +
					" they panic() on failure",
				Regex:    "^.*OrDie$",
				Coverage: 50,
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
	bytes, _ := yaml.Marshal(&config)
	return string(bytes)
}

const configFile = "golang-coverage-pre-commit.yaml"

var exampleConfig = flag.Bool("example_config", false, "output an example config and exit")

// parseYAMLConfig parses raw YAML into a Config, checks it for correctness, and
// compiles every regex for speed.
func parseYAMLConfig(yamlConf []byte) (Config, error) {
	var config Config
	if err := yaml.Unmarshal(yamlConf, &config); err != nil {
		return config, fmt.Errorf("failed parsing YAML: %w", err)
	}
	if config.Default < 0 || config.Default > 100 {
		return config, fmt.Errorf("default coverage is outside the range 0-100")
	}
	for i := range config.Functions {
		config.Functions[i].compiledRegex = regexp.MustCompile(config.Functions[i].Regex)
		if config.Functions[i].Coverage < 0 || config.Functions[i].Coverage > 100 {
			return config, fmt.Errorf("coverage is outside the range 0-100 in %v", config.Functions[i])
		}
	}
	for i := range config.Filenames {
		config.Filenames[i].compiledRegex = regexp.MustCompile(config.Filenames[i].Regex)
		if config.Filenames[i].Coverage < 0 || config.Filenames[i].Coverage > 100 {
			return config, fmt.Errorf("coverage is outside the range 0-100 in %v", config.Filenames[i])
		}
	}
	return config, nil
}

func realMain(args []string) (string, error) {
	if len(args) > 0 {
		return "", fmt.Errorf("unexpected arguments: %v", args)
	}
	if *exampleConfig {
		return makeExampleConfig(), nil
	}
	if _, err := os.Stat(configFile); err != nil {
		return "", fmt.Errorf("missing config: %v\n\n%v", configFile, makeExampleConfig())
	}
	bytes, err := os.ReadFile(configFile)
	if err != nil {
		return "", fmt.Errorf("failed reading config %v: %w", configFile, err)
	}
	config, err := parseYAMLConfig(bytes)
	if err != nil {
		return "", fmt.Errorf("failed parsing config %v: %w", configFile, err)
	}
	fmt.Printf("%v", config)
	return "", nil
}

func main() {
	flag.Parse()
	output, err := realMain(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
		os.Exit(1)
	}
	if output != "" {
		fmt.Print(output)
	}
}
