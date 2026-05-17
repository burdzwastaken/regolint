# regolint

[![CI](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml/badge.svg)](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/burdzwastaken/regolint)](https://github.com/burdzwastaken/regolint/releases/latest)
[![License](https://img.shields.io/github/license/burdzwastaken/regolint)](LICENSE)

<p align="center">
  <img src="assets/regolint-gopher.png" width="180" alt="regolint mascot">
</p>

Rego-powered linting for Go.

regolint lets you write custom Go lint rules as [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies. Policies query structured Go source metadata, so custom checks can be declarative, package-aware and testable with OPA.

- Write rules in Rego instead of Go analyzers
- Analyze files or whole packages
- Return optional fix suggestions
- Run standalone or as a golangci-lint module plugin

## Install

regolint requires Go 1.26 or newer when installing from source.

```bash
go install github.com/burdzwastaken/regolint/cmd/regolint@latest
```

`go install` installs only the binary. Bundled policies are not embedded, so copy them from the module cache:

```bash
moddir=$(go list -m -f '{{.Dir}}' github.com/burdzwastaken/regolint@v1.1.0)
cp -R "$moddir/policies" ./policies
regolint --policy-dir ./policies ./...
```

Use the same module version you installed, or `@latest` after the release is available.

## Quick start

```bash
regolint --policy-dir ./policies ./...
regolint --policy-dir ./policies --format json ./...
regolint --policy-dir ./policies --format sarif ./...
regolint --policy-dir ./policies --debug --dry-run ./pkg/...
regolint --version
```

`--policy-dir` defaults to `./policies`, recursively loads `.rego` files and ignores `*_test.rego`. The standalone CLI uses `--policy-dir`; `policy-files` is available in golangci-lint plugin settings.

### Exit codes

| Code | Meaning                                                                             |
|------|-------------------------------------------------------------------------------------|
| `0`  | Completed successfully with no violations, or no policies were found.               |
| `1`  | Policy violations were found, or required package arguments were missing.           |
| `2`  | Execution error, such as policy parse errors, package loading errors or bad output. |

## golangci-lint plugin

regolint integrates with golangci-lint as a [module plugin](https://golangci-lint.run/docs/plugins/module-plugins/).

Create `.custom-gcl.yml`:

```yaml
version: v2.12.2
plugins:
  - module: 'github.com/burdzwastaken/regolint'
    import: 'github.com/burdzwastaken/regolint/plugin'
    version: v1.1.0
```

Build the custom binary:

```bash
golangci-lint custom
```

The `version` in `.custom-gcl.yml` should match the `golangci-lint` binary you use to run `golangci-lint custom`.

Configure `.golangci.yml`:

```yaml
linters:
  enable:
    - regolint
  settings:
    custom:
      regolint:
        type: module
        settings:
          policy-dir: ./policies
          policy-files:
            - ./extra/security.rego
          disabled:
            - musttag
          options:
            builderonly:
              types:
                - ClientConfig
                - example.com/project.ServerConfig
              allowed_functions:
                - NewClientConfigBuilder
            builderchain:
              types:
                - ClientConfigBuilder
              method_prefixes:
                - With
                - Set
              require_pointer_return: true
            importboundaries:
              rules:
                - from: .*/internal/infrastructure(/.*)?$
                  forbidden:
                    - .*/internal/application(/.*)?$
                  message: infrastructure must not import application
            constructorinterfaces:
              dependency_rules:
                - parameter_names:
                    - db
                    - client
                  forbidden_type_patterns:
                    - ^\*?database/sql\.DB$
                    - ^\*?net/http\.Client$
                  message: constructors should accept interfaces for dependencies
            exposedinternals:
              forbidden_types:
                - internal/cache.Entry
              forbidden_type_patterns:
                - ^example\.com/project/internal/.*
              allowed_types:
                - internal/cache.PublicSnapshot
              allowed_functions:
                - NewInternalAdapter
              check_parameters: true
              check_returns: true
              check_fields: true
            functionaloptions:
              max_parameters: 3
              constructor_prefixes:
                - New
              option_suffixes:
                - Option
              require_option_application: true
            exclude:
              - "**/vendor/**"
              - "**/*_test.go"
```

Configured rule options are available to Rego policies at `input.rule_options.<rule>`.

Common bundled rule options:

| Rule                | Option                       | Description                                                |
|---------------------|------------------------------|------------------------------------------------------------|
| `builderonly`       | `types`                      | Type names or identities that must use builder creation.   |
| `builderonly`       | `allowed_functions`          | Functions allowed to construct configured types directly.  |
| `builderchain`      | `types`                      | Builder receiver types whose chain methods must return it. |
| `builderchain`      | `method_prefixes`            | Chainable method prefixes. Defaults to `With` and `Set`.   |
| `builderchain`      | `allowed_methods`            | Builder methods exempt from chain return checks.           |
| `builderchain`      | `require_pointer_return`     | Require chain methods to return a pointer builder type.    |
| `constructorinterfaces` | `dependency_rules`        | Constructor dependency type rules for interface boundaries. |
| `exposedinternals`  | `forbidden_types`            | Internal type names or identities forbidden in exported APIs. |
| `exposedinternals`  | `forbidden_type_patterns`    | Regex patterns for internal types forbidden in exported APIs. |
| `exposedinternals`  | `allowed_types`              | Internal types exempt from exported API checks.            |
| `exposedinternals`  | `allowed_functions`          | Exported functions exempt from exposed internal checks.    |
| `exposedinternals`  | `check_parameters`           | Check exported function parameters. Defaults to `true`.    |
| `exposedinternals`  | `check_returns`              | Check exported function returns. Defaults to `true`.       |
| `exposedinternals`  | `check_fields`               | Check exported struct fields. Defaults to `true`.          |
| `functionaloptions` | `max_parameters`             | Maximum non-context constructor parameters before flagging. |
| `functionaloptions` | `constructor_prefixes`       | Constructor name prefixes to check. Defaults to `New`.     |
| `functionaloptions` | `option_suffixes`            | Variadic option type suffixes. Defaults to `Option`.       |
| `functionaloptions` | `allowed_functions`          | Constructor functions exempt from this rule.               |
| `functionaloptions` | `require_option_application` | Require constructors to apply or forward variadic options. |
| `forbidigo`         | `identifiers`                | Identifier names to forbid.                                |
| `forbidigo`         | `calls`                      | Function or method call names to forbid.                   |
| `forbidigo`         | `strings`                    | String literals to forbid.                                 |
| `goheader`          | `required_pattern`           | Regular expression required in the file header.            |
| `importboundaries`  | `rules`                      | Regex-based package/import boundary rules.                 |
| `importas`          | `aliases`                    | Import path to required alias mapping.                     |

Run with the custom binary:

```bash
./custom-gcl run ./...
```

## Writing policies

Policies use [Rego v1 syntax](https://www.openpolicyagent.org/docs/latest/policy-language/) and must live under `regolint.rules.<category>.<rule>` so regolint can discover `deny` rules.

```rego
package regolint.rules.imports.banned

metadata := {
    "id": "depguard",
    "severity": "error",
    "description": "Prevents use of banned packages",
}

banned_packages := {"unsafe", "github.com/deprecated/pkg"}

deny contains violation if {
    some imp in input.imports
    imp.path in banned_packages

    violation := {
        "message": sprintf("Import of banned package '%s'", [imp.path]),
        "position": imp.position,
        "rule": metadata.id,
    }
}
```

Violations returned from `deny` use this shape:

| Field      | Required | Description                                                      |
|------------|----------|------------------------------------------------------------------|
| `message`  | Yes      | Human-readable violation message.                                |
| `rule`     | Yes      | Rule ID used in output, configuration and `nolint` directives.   |
| `position` | Yes      | Source location. Set `file`, `line` and `column` when available. |
| `severity` | No       | Optional severity. Defaults to `error` in text output.           |
| `fix`      | No       | Optional fix description and text edits.                         |

Example fix payload:

```json
{
  "fix": {
    "description": "Replace deprecated call",
    "edits": [
      {
        "position": {"file": "example.go", "line": 12, "column": 3},
        "old_text": "old",
        "new_text": "new"
      }
    ]
  }
}
```

## Policy input

Policies receive either a single-file `CodeContext` or package-wide `PackageContext`.

Common `CodeContext` fields:

| Field                  | Description                       |
|------------------------|-----------------------------------|
| `file_path`            | Absolute path to the source file  |
| `module_path`          | Go module path                    |
| `package`              | Package name, path and doc        |
| `imports`              | Import declarations               |
| `functions`            | Function and method declarations  |
| `types`                | Type declarations                 |
| `variables`            | Package-level variables           |
| `constants`            | Constants                         |
| `calls`                | Function and method calls         |
| `comments`             | Source comments                   |
| `literals`             | Literal expressions               |
| `composite_literals`   | Composite literal expressions     |
| `nolints`              | `nolint` suppression directives   |
| `range_loops`          | Range loop metadata               |
| `resource_acquires`    | Resource-producing assignments    |
| `resource_closes`      | Resource close calls              |
| `resource_errs`        | Resource error-check calls        |
| `subtests`             | Subtest callback metadata         |
| `rule_options`         | Configured options keyed by rule  |

Common `PackageContext` fields:

| Field                    | Description                            |
|--------------------------|----------------------------------------|
| `module_path`            | Go module path                         |
| `package`                | Package name, path and doc             |
| `files`                  | All `CodeContext` objects              |
| `all_imports`            | Deduplicated imports across files      |
| `all_functions`          | All functions across files             |
| `all_types`              | All types across files                 |
| `all_variables`          | All variables across files             |
| `all_constants`          | All constants across files             |
| `all_comments`           | All comments across files              |
| `all_literals`           | All literals across files              |
| `all_composite_literals` | All composite literals across files    |
| `all_calls`              | All calls across files                 |
| `all_resource_acquires`  | All resource acquisitions across files |
| `rule_options`           | Configured options keyed by rule       |

Useful built-ins:

| Built-in                         | Description                           |
|----------------------------------|---------------------------------------|
| `go.matches_pattern(str, regex)` | Check if string matches regex pattern |
| `go.is_exported(name)`           | Check if identifier is exported       |
| `go.is_test_file(filename)`      | Check if file is a test file          |
| `go.package_name(import_path)`   | Extract package name from import path |

Full schema reference: [docs/policy-input.md](docs/policy-input.md).

Bundled helper libraries can be imported from `data.regolint.lib.*`. The `type_ref` helper keeps type-aware policies concise:

```rego
import data.regolint.lib.type_ref

deny contains violation if {
    some fn in input.functions
    some param in fn.parameters
    type_ref.exposes(param, [], ["/internal/"], [])

    violation := {
        "message": sprintf("%s exposes an internal type", [fn.name]),
        "position": fn.position,
        "rule": "nointernalapi",
    }
}
```

Useful helpers include `type_ref.matches`, `type_ref.pattern_matches`, `type_ref.is_named`, `type_ref.children` and `type_ref.exposes`.

## Examples

### Banned imports

```rego
package regolint.rules.imports.banned

deny contains violation if {
    some imp in input.imports
    imp.path == "unsafe"
    violation := {
        "message": "Import of 'unsafe' is not allowed",
        "position": imp.position,
        "rule": "depguard",
    }
}
```

### Package documentation

```rego
package regolint.rules.package.documentation

deny contains violation if {
    some fn in input.all_functions
    fn.is_exported
    not fn.is_test
    count(fn.comments) == 0

    violation := {
        "message": sprintf("Exported function '%s' should have documentation", [fn.name]),
        "position": fn.position,
        "rule": "doccheck",
    }
}
```

More examples live in `policies/`.

## Bundled rules

The `policies/` directory contains bundled policies you can use directly or copy into your project and customize.

Status meanings:

- **Full**: Implements the core rule behavior for the metadata regolint exposes.
- **Partial**: Covers common cases, but omits edge cases that need type information, deeper control flow or whole-program analysis.
- **Heuristic**: Uses syntactic pattern matching and may produce false positives or false negatives in unusual code.

See the full inventory in [docs/bundled-rules.md](docs/bundled-rules.md).

## Limitations

regolint policies operate on structured metadata extracted from Go syntax. This keeps rules easy to write and test, but it is not a replacement for every compiler, type-checker or whole-program analyzer.

- Some bundled policies are heuristic approximations of existing Go linters.
- Package-wide policies analyze one package at a time, not the whole dependency graph.
- Rules that need precise type information, alias analysis, interprocedural control flow, SSA or build-tag-specific behavior are intentionally partial or deferred.
- Bundled policies are intended as strong starting points and may need project-specific configuration or `nolint` suppressions.

## Testing policies

Use OPA's built-in testing framework:

```rego
package regolint.rules.imports.banned_test

import data.regolint.rules.imports.banned

test_detects_unsafe if {
    violations := banned.deny with input as {
        "imports": [{"path": "unsafe", "position": {"line": 5}}]
    }
    count(violations) == 1
}
```

Run tests:

```bash
opa test ./policies -v
```

## License

MIT
