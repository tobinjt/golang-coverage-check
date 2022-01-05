package main

import (
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Rule represents a single function or filename rule.
type Rule struct {
	// Comment is not interpreted or used; it is provided as a structured way of
	// adding comments to an entry, so that automated editing is easier.
	Comment string
	// The regex used when matching against a function or filename.
	Regex string
	// The required coverage level; this is a floating point percentage, so it
	// should be >= 0 and <= 100.
	Coverage float64
	// TODO: figure out the right type.
	// compiledRegex string
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

func realMain(args []string) ([]string, error) {
	if len(args) > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", args)
	}
	if *exampleConfig {
		return []string{makeExampleConfig()}, nil
	}
	if _, err := os.Stat(configFile); err != nil {
		return nil, fmt.Errorf("missing config: %v\n\n%v", configFile, makeExampleConfig())
	}
	return nil, nil
}

func main() {
	flag.Parse()
	_, err := realMain(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
		os.Exit(1)
	}
}
