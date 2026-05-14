# regolint

[![CI](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml/badge.svg)](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/burdzwastaken/regolint)](https://github.com/burdzwastaken/regolint/releases/latest)
[![License](https://img.shields.io/github/license/burdzwastaken/regolint)](LICENSE)

Rego powered linting for Go.

## Description

regolint is a linter that lets you define custom Go linting rules using [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), the policy language from Open Policy Agent. Instead of writing Go code to implement custom analyzers, you write declarative policies that query a structured representation of your code.

**Why regolint?**

- **Declarative** - Describe what should be true, not how to check it
- **Testable** - Unit test your policies with OPA's built-in testing framework
- **Flexible** - Query imports, functions, types, calls and more
- **Package-wide analysis** - Analyze entire packages, not just single files
- **Auto-fix suggestions** - Policies can suggest how to fix violations

## Installation

regolint requires Go 1.26 or newer when installing from source.

```bash
go install github.com/burdzwastaken/regolint/cmd/regolint@latest
```

`go install` installs only the `regolint` binary. The bundled policies are not embedded in the binary; copy them from the module cache into your project:

```bash
moddir=$(go list -m -f '{{.Dir}}' github.com/burdzwastaken/regolint@v1.1.0)
cp -R "$moddir/policies" ./policies
regolint --policy-dir ./policies ./...
```

Use the same module version you installed, or `@latest` after the release is available.

## Usage

### Standalone

```bash
# run with policies from a directory; defaults to ./policies
# recursively loads .rego files and ignores *_test.rego
regolint --policy-dir ./policies ./...

# output as JSON
regolint --policy-dir ./policies --format json ./...

# output as SARIF (for GitHub Advanced Security)
regolint --policy-dir ./policies --format sarif ./...

# debug mode - show the CodeContext passed to policies
regolint --policy-dir ./policies --debug --dry-run ./pkg/...

# show version
regolint --version
```

The standalone CLI uses `--policy-dir`. `policy-files` is available in golangci-lint plugin settings.

### Exit Codes

| Code | Meaning                                                                             |
|------|-------------------------------------------------------------------------------------|
| `0`  | Completed successfully with no violations, or no policies were found.               |
| `1`  | Policy violations were found, or required package arguments were missing.           |
| `2`  | Execution error, such as policy parse errors, package loading errors or bad output. |

### With golangci-lint

regolint integrates with golangci-lint as a [module plugin](https://golangci-lint.run/docs/plugins/module-plugins/).

First, create `.custom-gcl.yml` to build a custom golangci-lint binary with regolint:

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

Then configure regolint in your `.golangci.yml`:

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
          exclude:
            - "**/vendor/**"
            - "**/*_test.go"
```

Run with your custom binary:

```bash
./custom-gcl run ./...
```

## Writing Policies

Policies use [Rego v1 syntax](https://www.openpolicyagent.org/docs/latest/policy-language/) and follow a standard structure:

Policy packages must live under `regolint.rules.<category>.<rule>` so regolint can discover `deny` rules, for example `package regolint.rules.imports.banned`.

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

### Violation Object

Policies return violations from `deny`. A violation should use this shape:

```json
{
  "message": "Human-readable finding",
  "rule": "rule-id",
  "severity": "error",
  "position": {
    "file": "example.go",
    "line": 12,
    "column": 3
  },
  "fix": {
    "description": "Optional fix description",
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

| Field      | Required | Description                                                      |
|------------|----------|------------------------------------------------------------------|
| `message`  | Yes      | Human-readable violation message.                                |
| `rule`     | Yes      | Rule ID used in output, configuration and `nolint` directives.   |
| `position` | Yes      | Source location. Set `file`, `line` and `column` when available. |
| `severity` | No       | Optional severity. Defaults to `error` in text output.           |
| `fix`      | No       | Optional auto-fix description and text edits.                    |

### CodeContext Schema (Single File)

Policies receive a `CodeContext` as input with the following structure:

| Field               | Type   | Description                                  |
|---------------------|--------|----------------------------------------------|
| `file_path`         | string | Absolute path to the source file             |
| `module_path`       | string | Go module path                               |
| `package`           | object | Package name, path and doc                   |
| `imports`           | array  | Import declarations                          |
| `functions`         | array  | Function and method declarations             |
| `types`             | array  | Type declarations (struct, interface, alias) |
| `variables`         | array  | Package-level variables                      |
| `constants`         | array  | Constants                                    |
| `lines`             | array  | Source line metadata                         |
| `comments`          | array  | Source comments                              |
| `literals`          | array  | Literal expressions                          |
| `returns`           | array  | Return statements                            |
| `ifs`               | array  | If statements and direct returns             |
| `type_assertions`   | array  | Type assertion expressions                   |
| `make_slices`       | array  | Slice make expressions assigned to targets   |
| `appends`           | array  | Append calls assigned to targets             |
| `resource_acquires` | array  | Resource-producing assignments               |
| `resource_closes`   | array  | Resource close calls                         |
| `resource_errs`     | array  | Resource error-check calls                   |
| `subtests`          | array  | Subtest callback metadata                    |
| `range_loops`       | array  | Range loop metadata                          |
| `loop_var_copies`   | array  | Redundant range loop variable copies         |
| `blank_assignments` | array  | Assignments containing blank identifiers     |
| `decl_groups`       | array  | Top-level declaration groups                 |
| `declarations`      | array  | Top-level declarations in source order       |
| `calls`             | array  | Function and method calls                    |
| `type_usages`       | array  | References to types                          |
| `field_accesses`    | array  | Field access expressions                     |
| `nolints`           | array  | nolint suppression directives                |

### Type Reference

#### ImportInfo (`input.imports[]`)

| Field      | Type   | Description                                |
|------------|--------|--------------------------------------------|
| `path`     | string | Import path (e.g., `"fmt"`)                |
| `alias`    | string | Import alias if any (e.g., `"_"`)          |
| `position` | object | Source location (`file`, `line`, `column`) |

#### FunctionInfo (`input.functions[]`)

| Field           | Type    | Description                                |
|-----------------|---------|--------------------------------------------|
| `name`          | string  | Function name                              |
| `receiver`      | string  | Receiver type for methods (e.g., `"*Foo"`) |
| `parameters`    | array   | Parameters (`name`, `type`)                |
| `returns`       | array   | Return values (`name`, `type`)             |
| `is_exported`   | boolean | Whether function is exported               |
| `is_test`       | boolean | Whether function is a test                 |
| `has_naked_ret` | boolean | Whether function has a naked return        |
| `complexity`    | integer | Cyclomatic complexity                      |
| `max_if_depth`  | integer | Maximum nested if depth                    |
| `line_count`    | integer | Number of lines in function body           |
| `position`      | object  | Source location                            |
| `comments`      | array   | Doc comments                               |
| `annotations`   | object  | Parsed annotations from comments           |

#### TypeInfo (`input.types[]`)

| Field         | Type    | Description                                    |
|---------------|---------|------------------------------------------------|
| `name`        | string  | Type name                                      |
| `kind`        | string  | `"struct"`, `"interface"`, `"alias"`, `"func"` |
| `is_exported` | boolean | Whether type is exported                       |
| `fields`      | array   | Struct fields (see FieldInfo)                  |
| `methods`     | array   | Methods (see MethodInfo)                       |
| `embeds`      | array   | Embedded type names                            |
| `implements`  | array   | Interfaces this type implements                |
| `position`    | object  | Source location                                |
| `doc`         | string  | Doc comment                                    |

#### CommentInfo (`input.comments[]`)

| Field           | Type    | Description                                 |
|-----------------|---------|---------------------------------------------|
| `text`          | string  | Comment text without comment markers        |
| `raw`           | string  | Raw source comment text                     |
| `is_first_line` | boolean | Whether this is the first line of a comment |
| `position`      | object  | Source location (`file`, `line`, `column`)  |

#### LineInfo (`input.lines[]`)

| Field      | Type    | Description                                |
|------------|---------|--------------------------------------------|
| `number`   | integer | Source line number                         |
| `length`   | integer | Source line length in bytes                |
| `position` | object  | Source location (`file`, `line`, `column`) |

#### LiteralInfo (`input.literals[]`)

| Field         | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `kind`        | string | Literal kind (`int`, `float`, `imag`, `char`, `string`) |
| `value`       | string | Literal source text                                     |
| `in_function` | string | Function containing this literal                        |
| `position`    | object | Source location (`file`, `line`, `column`)              |

#### ReturnInfo (`input.returns[]`)

| Field      | Type    | Description                                |
|------------|---------|--------------------------------------------|
| `function` | string  | Function containing this return statement  |
| `receiver` | string  | Receiver type for method returns           |
| `results`  | array   | Return result expressions as strings       |
| `is_naked` | boolean | Whether this is a bare return statement    |
| `position` | object  | Source location (`file`, `line`, `column`) |

#### IfInfo (`input.ifs[]`)

| Field            | Type    | Description                                      |
|------------------|---------|--------------------------------------------------|
| `function`       | string  | Function containing this if statement            |
| `receiver`       | string  | Receiver type for method if statements           |
| `condition`      | string  | If condition expression as a string              |
| `error_var`      | string  | Error variable name from `err != nil` conditions |
| `is_err_not_nil` | boolean | Whether condition contains `<ident> != nil`      |
| `returns`        | array   | Direct return statements in the if body          |
| `position`       | object  | Source location (`file`, `line`, `column`)       |

#### TypeAssertInfo (`input.type_assertions[]`)

| Field            | Type    | Description                                |
|------------------|---------|--------------------------------------------|
| `expr`           | string  | Asserted expression                        |
| `asserted_type`  | string  | Target type of the assertion               |
| `in_function`    | string  | Function containing this assertion         |
| `context`        | string  | Usage context (`assign`, `return`, etc.)   |
| `is_comma_ok`    | boolean | Whether assertion uses comma-ok form       |
| `assignment_tok` | string  | Assignment token if in assignment context  |
| `value_target`   | string  | Value target name for comma-ok assertions  |
| `ok_target`      | string  | ok target name for comma-ok assertions     |
| `position`       | object  | Source location (`file`, `line`, `column`) |

#### MakeSliceInfo (`input.make_slices[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Assignment target receiving the slice      |
| `len_arg`     | string  | Length argument passed to `make`           |
| `cap_arg`     | string  | Capacity argument passed to `make`         |
| `has_cap`     | boolean | Whether a capacity argument was provided   |
| `in_function` | string  | Function containing this expression        |
| `position`    | object  | Source location (`file`, `line`, `column`) |

#### AppendInfo (`input.appends[]`)

| Field         | Type   | Description                                |
|---------------|--------|--------------------------------------------|
| `target`      | string | Assignment target receiving append result  |
| `source`      | string | First argument passed to `append`          |
| `in_function` | string | Function containing this append call       |
| `position`    | object | Source location (`file`, `line`, `column`) |

#### ResourceInfo (`input.resource_acquires[]`)

| Field         | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `kind`        | string | Resource kind (`http_response`, `sql_rows`, `sql_stmt`) |
| `target`      | string | Assignment target receiving the resource                |
| `source`      | string | Producing call expression                               |
| `in_function` | string | Function containing this acquisition                    |
| `position`    | object | Source location (`file`, `line`, `column`)              |

#### ResourceClose (`input.resource_closes[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Closed resource expression                 |
| `is_defer`    | boolean | Whether the close call is deferred         |
| `in_function` | string  | Function containing this close call        |
| `position`    | object  | Source location (`file`, `line`, `column`) |

#### ResourceErr (`input.resource_errs[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Resource whose `Err` method is called      |
| `is_checked`  | boolean | Whether the error result is checked        |
| `in_function` | string  | Function containing this error check       |
| `position`    | object  | Source location (`file`, `line`, `column`) |

#### SubtestInfo (`input.subtests[]`)

| Field          | Type    | Description                                |
|----------------|---------|--------------------------------------------|
| `name`         | string  | Static subtest name when available         |
| `function`     | string  | Parent test function name                  |
| `test_param`   | string  | Subtest `*testing.T` parameter name        |
| `has_parallel` | boolean | Whether subtest calls `t.Parallel()`       |
| `position`     | object  | Source location (`file`, `line`, `column`) |

#### RangeLoopInfo (`input.range_loops[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `key`         | string  | Range key variable name                    |
| `value`       | string  | Range value variable name                  |
| `source`      | string  | Ranged expression                          |
| `in_function` | string  | Function containing this range loop        |
| `end_line`    | integer | Last source line of this range loop body   |
| `position`    | object  | Source location (`file`, `line`, `column`) |

#### LoopVarCopyInfo (`input.loop_var_copies[]`)

| Field         | Type   | Description                                |
|---------------|--------|--------------------------------------------|
| `variable`    | string | Copied range variable name                 |
| `kind`        | string | Loop variable kind (`key` or `value`)      |
| `in_function` | string | Function containing this copy              |
| `position`    | object | Source location (`file`, `line`, `column`) |

#### BlankAssignInfo (`input.blank_assignments[]`)

| Field         | Type    | Description                                  |
|---------------|---------|----------------------------------------------|
| `blank_count` | integer | Number of blank identifiers on the left side |
| `total_count` | integer | Total left-side expressions                  |
| `in_function` | string  | Function containing this assignment          |
| `position`    | object  | Source location (`file`, `line`, `column`)   |

#### DeclGroupInfo (`input.decl_groups[]`)

| Field        | Type    | Description                                         |
|--------------|---------|-----------------------------------------------------|
| `kind`       | string  | Declaration kind (`const`, `import`, `type`, `var`) |
| `count`      | integer | Number of items in the declaration                  |
| `is_grouped` | boolean | Whether the declaration uses grouped form           |
| `block_id`   | integer | File-local declaration group identifier             |
| `position`   | object  | Source location (`file`, `line`, `column`)          |

#### DeclInfo (`input.declarations[]`)

| Field      | Type   | Description                                                 |
|------------|--------|-------------------------------------------------------------|
| `kind`     | string | Declaration kind (`import`, `const`, `var`, `type`, `func`) |
| `name`     | string | Declaration name                                            |
| `position` | object | Source location (`file`, `line`, `column`)                  |

#### FieldInfo (`input.types[].fields[]`)

| Field         | Type    | Description                            |
|---------------|---------|----------------------------------------|
| `name`        | string  | Field name                             |
| `type`        | string  | Field type                             |
| `tags`        | string  | Struct tags (e.g., `` `json:"foo"` ``) |
| `is_exported` | boolean | Whether field is exported              |
| `is_embedded` | boolean | Whether field is an embedded type      |
| `position`    | object  | Source location                        |

#### VariableInfo (`input.variables[]`, `input.constants[]`)

| Field         | Type    | Description                                  |
|---------------|---------|----------------------------------------------|
| `name`        | string  | Variable/constant name                       |
| `type`        | string  | Type if declared                             |
| `is_exported` | boolean | Whether exported                             |
| `is_const`    | boolean | Whether it's a constant                      |
| `value`       | string  | Literal value if available                   |
| `in_function` | string  | Containing function (empty if package-level) |
| `block_id`    | integer | Declaration group identifier                 |
| `uses_iota`   | boolean | Whether this const derives from `iota`       |
| `position`    | object  | Source location                              |

#### NolintDirective (`input.nolints[]`)

| Field      | Type    | Description                 |
|------------|---------|-----------------------------|
| `line`     | integer | Directive line              |
| `end_line` | integer | Optional range end line     |
| `rules`    | array   | Suppressed rule IDs         |
| `reason`   | string  | Optional suppression reason |

#### CallInfo (`input.calls[]`)

| Field           | Type    | Description                               |
|-----------------|---------|-------------------------------------------|
| `function`      | string  | Called function name                      |
| `package`       | string  | Package of called function                |
| `receiver`      | string  | Receiver variable name for method calls   |
| `receiver_type` | string  | Receiver type for method calls            |
| `args`          | array   | Argument expressions as strings           |
| `in_function`   | string  | Function containing this call             |
| `in_func_lit`   | boolean | Whether the call is inside a func literal |
| `position`      | object  | Source location                           |

#### TypeUsageInfo (`input.type_usages[]`)

| Field         | Type   | Description                                     |
|---------------|--------|-------------------------------------------------|
| `type_name`   | string | Name of the type being used                     |
| `package`     | string | Package of the type                             |
| `in_function` | string | Function containing this usage                  |
| `context`     | string | Usage context (e.g., `"parameter"`, `"return"`) |
| `position`    | object | Source location                                 |

#### FieldAccessInfo (`input.field_accesses[]`)

| Field         | Type   | Description                     |
|---------------|--------|---------------------------------|
| `field`       | string | Accessed field name             |
| `receiver`    | string | Receiver expression             |
| `type`        | string | Type of the receiver            |
| `in_function` | string | Function containing this access |
| `position`    | object | Source location                 |

### PackageContext Schema (Package-wide)

For package-wide analysis, policies receive a `PackageContext`:

| Field                   | Type   | Description                                 |
|-------------------------|--------|---------------------------------------------|
| `module_path`           | string | Go module path                              |
| `package`               | object | Package name, path and doc                  |
| `files`                 | array  | All CodeContext objects in the package      |
| `all_imports`           | array  | Deduplicated imports across all files       |
| `all_functions`         | array  | All functions across all files              |
| `all_types`             | array  | All types across all files                  |
| `all_variables`         | array  | All variables across all files              |
| `all_constants`         | array  | All constants across all files              |
| `all_lines`             | array  | All source lines across all files           |
| `all_comments`          | array  | All comments across all files               |
| `all_literals`          | array  | All literals across all files               |
| `all_returns`           | array  | All return statements across all files      |
| `all_ifs`               | array  | All if statements across all files          |
| `all_type_assertions`   | array  | All type assertions across all files        |
| `all_make_slices`       | array  | All slice make expressions across all files |
| `all_appends`           | array  | All append calls across all files           |
| `all_resource_acquires` | array  | All resource acquisitions across all files  |
| `all_resource_closes`   | array  | All resource close calls across all files   |
| `all_resource_errs`     | array  | All resource error checks across all files  |
| `all_subtests`          | array  | All subtests across all files               |
| `all_range_loops`       | array  | All range loops across all files            |
| `all_loop_var_copies`   | array  | All loop variable copies across all files   |
| `all_blank_assignments` | array  | All blank assignments across all files      |
| `all_decl_groups`       | array  | All declaration groups across all files     |
| `all_declarations`      | array  | All declarations across all files           |
| `all_calls`             | array  | All calls across all files                  |

### Custom Built-ins

regolint provides Go-specific Rego built-ins:

| Built-in                         | Description                           |
|----------------------------------|---------------------------------------|
| `go.matches_pattern(str, regex)` | Check if string matches regex pattern |
| `go.is_exported(name)`           | Check if identifier is exported       |
| `go.is_test_file(filename)`      | Check if file is a test file          |
| `go.package_name(import_path)`   | Extract package name from import path |

### Auto-fix Suggestions

Policies can include fix suggestions:

```rego
deny contains violation if {
    some t in input.types
    t.is_exported
    t.doc == ""

    violation := {
        "message": sprintf("Exported type '%s' should have documentation", [t.name]),
        "position": t.position,
        "rule": "doccheck",
        "fix": {
            "description": sprintf("Add a doc comment above type %s", [t.name]),
        },
    }
}
```

## Policy Examples

### Banned Imports

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

### Layer Architecture

```rego
package regolint.rules.architecture.layers

layer_rules := {
    "domain": [],
    "application": ["domain"],
    "infrastructure": ["domain", "application"],
}

default get_layer(_) := "unknown"

get_layer(pkg) := layer if {
    parts := split(pkg, "/")
    layer := parts[count(parts) - 1]
    layer in object.keys(layer_rules)
}

deny contains violation if {
    current := get_layer(input.package.path)
    current != "unknown"

    some imp in input.imports
    imported := get_layer(imp.path)
    imported != "unknown"
    imported != current

    allowed := layer_rules[current]
    not imported in allowed

    violation := {
        "message": sprintf("'%s' cannot import from '%s'", [current, imported]),
        "position": imp.position,
        "rule": "archlayers",
    }
}
```

### Hardcoded Credentials

```rego
package regolint.rules.security.credentials

sensitive_patterns := ["password", "secret", "token", "apikey"]

deny contains violation if {
    some v in input.constants
    some pattern in sensitive_patterns
    contains(lower(v.name), pattern)
    violation := {
        "message": sprintf("Possible hardcoded credential: '%s'", [v.name]),
        "position": v.position,
        "rule": "hardcodedcreds",
    }
}
```

### Package Documentation (Package-wide)

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

## Rule Inventory

The `policies/` directory contains bundled policies you can use directly or copy into your project and customize. Some rules are direct structural checks, while others are partial or heuristic approximations of existing Go linters based on the metadata available in `CodeContext` and `PackageContext`.

Status meanings:

- **Full**: Implements the core rule behavior for the metadata regolint exposes.
- **Partial**: Covers common cases, but intentionally omits edge cases that need type information, deeper control flow or whole-program analysis.
- **Heuristic**: Uses syntactic pattern matching and may produce false positives or false negatives in unusual code.

| Category     | Policy                            | Rule ID                     | Status    | Notes                                                  |
|--------------|-----------------------------------|-----------------------------|-----------|--------------------------------------------------------|
| Architecture | `architecture/layers`             | `archlayers`                | Full      | Enforces configured layer import boundaries.           |
| Comment      | `comment/dupword`                 | `dupword`                   | Heuristic | Checks duplicate words in comments and strings.        |
| Comment      | `comment/godot`                   | `godot`                     | Heuristic | Checks comment punctuation with common ignore rules.   |
| Comment      | `comment/godox`                   | `godox`                     | Full      | Checks TODO/FIXME/HACK/BUG comment markers.            |
| Complexity   | `complexity/nestif`               | `nestif`                    | Full      | Checks maximum nested `if` depth.                      |
| Context      | `context/fatcontext`              | `fatcontext`                | Partial   | Checks context derivation inside range loops.          |
| Context      | `context/noctx`                   | `noctx`                     | Heuristic | Checks direct `http.NewRequest` calls.                 |
| Context      | `context/usage`                   | `contextcheck`              | Full      | Checks `context.Context` parameter position.           |
| Context      | `context/usage`                   | `contextname`               | Full      | Checks `context.Context` parameter names.              |
| Errors       | `errors/err113`                   | `err113`                    | Heuristic | Checks dynamic error creation and missing `%w`.        |
| Errors       | `errors/handling`                 | `wrapcheck`                 | Heuristic | Checks simple error wrapping patterns.                 |
| Errors       | `errors/nilerr`                   | `nilerr`                    | Partial   | Checks nil error returns after error guards.           |
| Errors       | `errors/nilnil`                   | `nilnil`                    | Partial   | Checks literal `nil, nil` style returns.               |
| Imports      | `imports/banned`                  | `depguard`                  | Full      | Prevents configured banned imports.                    |
| Imports      | `imports/exptostd`                | `exptostd`                  | Full      | Checks selected `x/exp` imports moved to stdlib.       |
| Imports      | `imports/importas`                | `importas`                  | Partial   | Checks configured import aliases.                      |
| Naming       | `naming/conventions`              | `interfacenaming`           | Heuristic | Checks project-specific interface naming conventions.  |
| Package      | `package/complexity`              | `funlen`                    | Full      | Checks function length.                                |
| Package      | `package/complexity`              | `gocyclo`                   | Full      | Checks cyclomatic complexity.                          |
| Package      | `package/documentation`           | `doccheck`                  | Full      | Checks exported symbol documentation.                  |
| Performance  | `performance/bodyclose`           | `bodyclose`                 | Heuristic | Checks common HTTP response close patterns.            |
| Performance  | `performance/makezero`            | `makezero`                  | Heuristic | Checks non-zero-length slices before append.           |
| Performance  | `performance/mirror`              | `mirror`                    | Heuristic | Checks bytes/strings mirror call opportunities.        |
| Performance  | `performance/perfsprint`          | `perfsprint`                | Heuristic | Checks simple inefficient `fmt` formatting.            |
| Performance  | `performance/prealloc`            | `prealloc`                  | Partial   | Checks range-loop appends without capacity.            |
| Security     | `security/bidichk`                | `bidichk`                   | Full      | Checks Unicode bidi control characters.                |
| Security     | `security/credentials`            | `hardcodedcreds`            | Heuristic | Checks likely hardcoded credential names/values.       |
| SQL          | `sql/rowserrcheck`                | `rowserrcheck`              | Heuristic | Checks common `Rows.Err` patterns.                     |
| SQL          | `sql/sqlclosecheck`               | `sqlclosecheck`             | Heuristic | Checks common SQL rows/statement close patterns.       |
| Structs      | `structs/tags`                    | `musttag`                   | Full      | Ensures exported fields have required tags.            |
| Style        | `style/asciicheck`                | `asciicheck`                | Partial   | Checks exposed identifier facts for non-ASCII text.    |
| Style        | `style/canonicalheader`           | `canonicalheader`           | Heuristic | Checks known HTTP header literals.                     |
| Style        | `style/containedctx`              | `containedctx`              | Heuristic | Checks syntactic `context.Context` struct fields.      |
| Style        | `style/copyloopvar`               | `copyloopvar`               | Partial   | Checks redundant range loop variable copies.           |
| Style        | `style/decorder`                  | `decorder`                  | Full      | Checks top-level declaration order.                    |
| Style        | `style/dogsled`                   | `dogsled`                   | Full      | Checks assignments with too many blank identifiers.    |
| Style        | `style/embeddedstructfieldcheck`  | `embeddedstructfieldcheck`  | Full      | Checks embedded field ordering.                        |
| Style        | `style/errname`                   | `errname`                   | Heuristic | Checks error naming conventions.                       |
| Style        | `style/forbidigo`                 | `forbidigo`                 | Heuristic | Checks configured forbidden code patterns.             |
| Style        | `style/forcetypeassert`           | `forcetypeassert`           | Partial   | Checks unchecked type assertions.                      |
| Style        | `style/gocheckcompilerdirectives` | `gocheckcompilerdirectives` | Partial   | Checks malformed compiler directives.                  |
| Style        | `style/gochecknoglobals`          | `gochecknoglobals`          | Full      | Checks package-level variables.                        |
| Style        | `style/gochecknoinits`            | `gochecknoinits`            | Full      | Checks `init` functions.                               |
| Style        | `style/goheader`                  | `goheader`                  | Full      | Checks configured file headers.                        |
| Style        | `style/goprintffuncname`          | `goprintffuncname`          | Heuristic | Checks printf-like function names.                     |
| Style        | `style/inamedparam`               | `inamedparam`               | Full      | Checks interface method parameter names.               |
| Style        | `style/interfacebloat`            | `interfacebloat`            | Partial   | Checks direct interface method counts.                 |
| Style        | `style/iotamixing`                | `iotamixing`                | Full      | Checks const blocks mixing iota and values.            |
| Style        | `style/lll`                       | `lll`                       | Full      | Checks line length in bytes.                           |
| Style        | `style/mnd`                       | `mnd`                       | Heuristic | Checks numeric literals against common allowlist.      |
| Style        | `style/nakedret`                  | `nakedret`                  | Full      | Checks naked returns with named results.               |
| Style        | `style/nolintlint`                | `nolintlint`                | Partial   | Checks basic nolint directive hygiene.                 |
| Style        | `style/nonamedreturns`            | `nonamedreturns`            | Full      | Checks named return values.                            |
| Style        | `style/nosprintfhostport`         | `nosprintfhostport`         | Heuristic | Checks likely host:port `fmt.Sprintf` calls.           |
| Style        | `style/predeclared`               | `predeclared`               | Partial   | Checks exposed declarations/params for built-in names. |
| Style        | `style/recvcheck`                 | `recvcheck`                 | Partial   | Checks receiver consistency by receiver text.          |
| Style        | `style/tagliatelle`               | `tagliatelle`               | Partial   | Checks selected struct tag naming conventions.         |
| Style        | `style/usestdlibvars`             | `usestdlibvars`             | Heuristic | Checks literals that should use stdlib constants.      |
| Test         | `test/paralleltest`               | `paralleltest`              | Heuristic | Checks test functions call `t.Parallel`.               |
| Test         | `test/testableexamples`           | `testableexamples`          | Partial   | Checks examples include output comments.               |
| Test         | `test/testpackage`                | `testpackage`               | Full      | Checks tests use an external package.                  |
| Test         | `test/thelper`                    | `thelper`                   | Heuristic | Checks likely helpers call `testing.T.Helper`.         |
| Test         | `test/tparallel`                  | `tparallel`                 | Heuristic | Checks subtests call `t.Parallel`.                     |
| Test         | `test/usetesting`                 | `usetesting`                | Partial   | Checks test code should use testing helpers.           |

## Limitations

regolint policies operate on structured metadata extracted from Go syntax. This keeps rules easy to write and test, but it is not a replacement for every compiler, type-checker or whole-program analyzer.

In particular:

- Some bundled policies are heuristic approximations of existing Go linters.
- Package-wide policies analyze one package at a time, not the whole dependency graph.
- Rules that need precise type information, alias analysis, interprocedural control flow, SSA or build-tag-specific behavior are intentionally partial or deferred.
- Bundled policies are intended as strong starting points and may need project-specific configuration or `nolint` suppressions.

## Testing Policies

Use OPA's built-in testing framework:

```rego
# policies/imports_test.rego
package regolint.rules.imports.banned_test

import data.regolint.rules.imports.banned

test_detects_unsafe if {
    violations := banned.deny with input as {
        "imports": [{"path": "unsafe", "position": {"line": 5}}]
    }
    count(violations) == 1
}

test_allows_safe_imports if {
    violations := banned.deny with input as {
        "imports": [{"path": "fmt", "position": {"line": 5}}]
    }
    count(violations) == 0
}
```

Run tests:

```bash
opa test ./policies -v
```

## License

MIT
