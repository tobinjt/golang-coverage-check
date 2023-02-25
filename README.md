# golang-coverage-pre-commit

A tool to check that Golang code has sufficient test coverage. This tool can be
used via <https://pre-commit.com> or standalone by running
`golang-coverage-pre-commit`.

## Quick start

### Bootstrapping a config

You can easily bootstrap a config that requires high coverage for new code and
the current coverage level for existing code to prevent a reduction in coverage.

```shell
golang-coverage-pre-commit --generate_config > .golang-coverage-pre-commit.yaml
```

### Pre-commit hook

Use the following stanza in `.pre-commit-config.yaml` to use this tool with
<https://pre-commit.com>.

```yaml
- repo: https://github.com/tobinjt/golang-coverage-pre-commit.git
  rev: v1.0
  hooks:
    - id: golang-coverage
```

## Configuration

A YAML config file named `.golang-coverage-pre-commit.yaml` is **_required_**.
None of the fields are required inside the file; an empty config is equivalent
to a config containing only `default_coverage: 0`. You can generate an example
config (shown below) by running `golang-coverage-pre-commit --example_config`.

### Example config

```yaml
comment:
  Comment is not interpreted or used; it is provided as a structured way of
  adding comments to a config, so that automated editing is easier.
default_coverage: 80
rules:
  - comment: Low coverage is acceptable for main()
    filename_regex: ""
    function_regex: ^main$
    receiver_regex: ""
    coverage: 50
  - comment:
      All the fooOrDie() functions should be fully tested because they panic()
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
```

### Fields in the config file

**_Top-level fields_**

- `comment`: unused by `golang-coverage-pre-commit`, it exists to support
  structured comments that survive de-serialisation and re-serialisation, e.g.
  when combining config snippets.
- `default_coverage`: this is the default required coverage level that is used
  when a coverage line is not matched by a more specific rule (see [Order of
  evaluation](#order-of-evaluation) below).
- `rules`: a list of rules (described below).

**_Rules_**

Rules have the following fields; `coverage` is required, and at least one regex
must be non-empty.

- `comment`: unused by `golang-coverage-pre-commit`, it exists to support
  structured comments that survive de-serialisation and re-serialisation, e.g.
  when combining config snippets.
- `filename_regex`: the regular expression that the filename is matched against.
  Ignored if empty.
- `function_regex`: the regular expression that the function name is matched
  against. Ignored if empty.
- `receiver_regex`: the regular expression that the method receiver name is
  matched against. Ignored if empty.
- `coverage`: the required coverage level for lines matched by this rule.

### Order of evaluation

Each line of coverage output (effectively, each function in your code) is
independently evaluated:

- Each rule is checked in the order provided in the config:

  - If a `filename_regex` was provided the filename must match it; an empty or
    missing `filename_regex` is ignored. The line number and the module name
    from `go.mod` are removed before matching (e.g.
    `github.com/tobinjt/golang-coverage-pre-commit/golang-coverage-pre-commit.go:81`
    becomes `golang-coverage-pre-commit.g0`). Note that `filename_regex` is a
    _regex_, not a _glob_.
  - If a `function_regex` was provided the function name must match it; an empty
    or missing `function_regex` is ignored.
  - If a `receiver_regex` was provided the method receiver name must match it;
    an empty or missing `receiver_regex` is ignored. You should not supply a
    `receiver_regex` unless the function is a method with a method receiver,
    otherwise the rule will not match.
  - If all checks pass the required coverage is compared against the actual
    coverage, and an error printed if the actual coverage is not high enough.
    The following rules will be skipped, allowing you to write more specific
    rules first followed by more general rules later.

- If no rules matched, `default_coverage` is compared against the actual
  coverage, and an error printed if the actual coverage is not high enough.

## FAQ

**How can I tell which lines of code have not been tested?**

Run `golang-coverage-pre-commit --browser` - it will open the coverage report in
your browser. If you're developing remotely this will not work, but you can
find the coverage report in `${TMPDIR}/cover<RANDOM>/coverage.html` so maybe you
can copy it to your local machine and open it from there?

**How can I debug rule matching?**

Run `golang-coverage-pre-commit --debug_matching` - each coverage line and the
rule that matches it will be printed. That tells you that the earlier rules in
your config did not match that line and the later rules in your config were not
reached.

**How can I pass different arguments to `go test`?**

You can't, they're hard-coded. If you need this please open an issue so we can
discuss it.

**Can I include one config in another?**

There's no facility for this, but hopefully it's relatively easy to write some
code to merge two config files. This is why comments are structured data rather
than `//` comments.

**How is coverage generated?**

Coverage will be generated by running:

```shell
go test --coverprofile="${filename}" --covermode=set
go tool cover --func="${filename}"
```

The output from the second command will be parsed to check whether it meets the
coverage requirements you define (see [Configuration](#configuration) above),
and an error message will be output for any functions not meeting your
requirements.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## Code of Conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) for details.

## License

Apache 2.0; see [`LICENSE`](LICENSE) for details.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.
