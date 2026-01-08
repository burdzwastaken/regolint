# regolint

[![CI](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml/badge.svg)](https://github.com/burdzwastaken/regolint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/burdzwastaken/regolint)](https://github.com/burdzwastaken/regolint/releases/latest)
[![License](https://img.shields.io/github/license/burdzwastaken/regolint)](LICENSE)

Policy-as-code for Go. Write lint rules in Rego, not Go.

## Description

regolint is a linter that lets you define custom Go linting rules using [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/), the policy language from Open Policy Agent. Instead of writing Go code to implement custom analyzers, you write declarative policies that query a structured representation of your code.

**Why regolint?**

- **No Go expertise required** - Define rules in Rego, a purpose-built policy language
- **Declarative** - Describe what should be true, not how to check it
- **Testable** - Unit test your policies with OPA's built-in testing framework
- **Flexible** - Query imports, functions, types, calls and more
- **Package-wide analysis** - Analyze entire packages, not just single files
- **Auto-fix suggestions** - Policies can suggest how to fix violations

## Installation

```bash
go install github.com/burdzwastaken/regolint/cmd/regolint@latest
```

## Usage

### Standalone

```bash
# run with policies from a directory
regolint --policy-dir ./policies ./...

# run with specific policy files
regolint --policy-dir ./policies ./...

# output as JSON
regolint --format json ./...

# output as SARIF (for GitHub Advanced Security)
regolint --format sarif ./...

# debug mode - show the CodeContext passed to policies
regolint --debug --dry-run ./pkg/...

# show version
regolint --version
```

### With golangci-lint

Add to your `.golangci.yml`:

```yaml
linters-settings:
  custom:
    regolint:
      type: module
      path: github.com/burdzwastaken/regolint/plugin
      settings:
        policy-dir: ./policies
        policy-files:
          - ./extra/security.rego
        disabled:
          - TAG001
        exclude:
          - "**/vendor/**"
          - "**/*_test.go"
```

## Writing Policies

Policies use [Rego v1 syntax](https://www.openpolicyagent.org/docs/latest/policy-language/) and follow a standard structure:

```rego
package regolint.rules.imports.banned

metadata := {
    "id": "IMP001",
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

### CodeContext Schema (Single File)

Policies receive a `CodeContext` as input with the following structure:

| Field         | Type   | Description                                  |
|---------------|--------|----------------------------------------------|
| `file_path`   | string | Absolute path to the source file             |
| `module_path` | string | Go module path                               |
| `package`     | object | Package name, path and doc                   |
| `imports`     | array  | Import declarations                          |
| `functions`   | array  | Function and method declarations             |
| `types`       | array  | Type declarations (struct, interface, alias) |
| `variables`   | array  | Package-level variables                      |
| `constants`   | array  | Constants                                    |
| `calls`       | array  | Function and method calls                    |

### PackageContext Schema (Package-wide)

For package-wide analysis, policies receive a `PackageContext`:

| Field           | Type   | Description                            |
|-----------------|--------|----------------------------------------|
| `module_path`   | string | Go module path                         |
| `package`       | object | Package name, path and doc             |
| `files`         | array  | All CodeContext objects in the package |
| `all_imports`   | array  | Deduplicated imports across all files  |
| `all_functions` | array  | All functions across all files         |
| `all_types`     | array  | All types across all files             |
| `all_variables` | array  | All variables across all files         |
| `all_constants` | array  | All constants across all files         |
| `all_calls`     | array  | All calls across all files             |

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
        "rule": "PKG001",
        "fix": {
            "description": sprintf("Add a doc comment above type %s", [t.name]),
        },
    }
}
```

## Example Policies

### Banned Imports

```rego
package regolint.rules.imports.banned

deny contains violation if {
    some imp in input.imports
    imp.path == "unsafe"
    violation := {
        "message": "Import of 'unsafe' is not allowed",
        "position": imp.position,
        "rule": "IMP001",
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

deny contains violation if {
    current := get_layer(input.package.path)
    some imp in input.imports
    imported := get_layer(imp.path)
    not imported in layer_rules[current]
    violation := {
        "message": sprintf("'%s' cannot import from '%s'", [current, imported]),
        "position": imp.position,
        "rule": "ARCH001",
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
        "rule": "SEC001",
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
        "rule": "PKG001",
    }
}
```

## Included Policies

| Policy                  | ID      | Description                                    |
|-------------------------|---------|------------------------------------------------|
| `imports/banned`        | IMP001  | Prevents use of banned packages                |
| `architecture/layers`   | ARCH001 | Enforces clean architecture layer dependencies |
| `naming/conventions`    | NAME001 | Enforces naming conventions for types          |
| `security/credentials`  | SEC001  | Prevents hardcoded credentials                 |
| `structs/tags`          | TAG001  | Ensures exported fields have required tags     |
| `errors/handling`       | ERR001  | Checks for proper error handling               |
| `context/usage`         | CTX001  | Checks for proper context.Context usage        |
| `package/documentation` | PKG001  | Checks that exported symbols have docs         |
| `package/complexity`    | PKG002  | Checks function complexity and length          |

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
