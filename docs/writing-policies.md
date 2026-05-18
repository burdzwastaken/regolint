# Writing policies

regolint policies are Rego modules that inspect structured Go source metadata. Use them for project-specific architecture, API, migration, security and style rules that are too specific for generic linters.

Policies should stay honest about their scope: they query source facts. They are not whole-program dataflow, taint analysis or a replacement for the Go compiler.

## Policy structure

Policies use Rego v1 syntax and must live under `regolint.rules.<category>.<rule>` so regolint can discover `deny` rules.

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
		"message": sprintf("Import of banned package %q", [imp.path]),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
```

Violation objects should include:

| Field      | Required | Description                                                    |
|------------|----------|----------------------------------------------------------------|
| `message`  | Yes      | Human-readable violation message.                              |
| `rule`     | Yes      | Stable rule ID used in output, config and `nolint` directives. |
| `position` | Yes      | Source location when available.                                |
| `severity` | No       | Optional severity.                                             |
| `fix`      | No       | Optional fix description and text edits.                       |

## CodeContext vs PackageContext

Single-file policies receive `CodeContext`. Use these when the rule can be checked from one file at a time.

Common fields:

```rego
input.file_path
input.module_path
input.package
input.imports
input.functions
input.types
input.comments
input.calls
input.rule_options
```

Package-wide policies receive `PackageContext`. Use these when the rule needs all files in a package.

Common package fields:

```rego
input.module_path
input.package
input.files
input.all_imports
input.all_functions
input.all_types
input.all_calls
input.rule_options
```

Full input reference: [policy-input.md](policy-input.md).

## Rule options

Prefer scoped options under `input.rule_options.<rule>`:

```yaml
options:
  importboundaries:
    rules:
      - from: .*/internal/infrastructure(/.*)?$
        forbidden:
          - .*/internal/application(/.*)?$
        message: infrastructure must not import application
```

Policy access:

```rego
options := object.get(object.get(input, "rule_options", {}), "importboundaries", {})
rules := object.get(options, "rules", [])
```

Keep options small and predictable. If a rule needs many arbitrary knobs, it may be better as an example custom policy than a bundled default.

## Testing policies

OPA tests live beside the policy and use an external `_test` package.

```rego
package regolint.rules.imports.banned_test

import data.regolint.rules.imports.banned

test_detects_unsafe_import if {
	violations := banned.deny with input as {
		"imports": [{
			"path": "unsafe",
			"position": {"file": "main.go", "line": 3, "column": 8},
		}],
	}

	count(violations) == 1
}

test_allows_safe_import if {
	violations := banned.deny with input as {
		"imports": [{"path": "fmt"}],
	}

	count(violations) == 0
}
```

Keep tests focused:

- Build only the input fields the policy reads.
- Test at least one denied case and one allowed case.
- Add option-specific tests for configurable behavior.
- Include realistic positions when the rule emits positions.

Run tests with:

```bash
opa test ./policies -v
opa test policies/style/exposedinternals.rego policies/style/exposedinternals_test.rego -v
```

## Using `type_ref`

regolint emits `type_ref` for function parameters, return values, struct fields and composite literals. Prefer `type_ref` over parsing rendered type strings.

Import the bundled helper library:

```rego
import data.regolint.lib.type_ref
```

Useful helpers:

| Helper                              | Use case                                             |
|-------------------------------------|------------------------------------------------------|
| `type_ref.matches(ref, name)`       | Match legacy `type`, `type_identity` or `type_ref`.  |
| `type_ref.pattern_matches(ref, re)` | Regex-match identity, display or package path.       |
| `type_ref.is_named(ref, pkg, name)` | Match a structured named type.                       |
| `type_ref.children(ref)`            | Return direct `elem`, `key` and `value` children.    |
| `type_ref.exposes(ref, f, p, a)`    | Match forbidden nested refs with same-node allowlist. |

Example: forbid exported APIs from exposing internal types, including nested types like `[]internal.Store` and `map[string]*internal.Store`.

```rego
package regolint.rules.style.no_internal_api

import data.regolint.lib.type_ref

options := object.get(object.get(input, "rule_options", {}), "no_internal_api", {})
forbidden_types := object.get(options, "forbidden_types", [])
forbidden_patterns := object.get(options, "forbidden_type_patterns", [])
allowed_types := object.get(options, "allowed_types", [])

deny contains violation if {
	some fn in input.functions
	fn.is_exported

	some ret in fn.returns
	type_ref.exposes(ret, forbidden_types, forbidden_patterns, allowed_types)

	violation := {
		"message": sprintf("%s exposes a forbidden internal type", [fn.name]),
		"position": fn.position,
		"rule": "no_internal_api",
	}
}
```

Config:

```yaml
options:
  no_internal_api:
    forbidden_type_patterns:
      - ^example\.com/project/internal/.*
    allowed_types:
      - example.com/project/internal/store.PublicSnapshot
```

## Example: architecture boundary

Architecture rules usually compare the current package path with import paths.

```rego
package regolint.rules.architecture.domain_boundary

options := object.get(object.get(input, "rule_options", {}), "domain_boundary", {})
domain_prefix := object.get(options, "domain_prefix", "")
transport_prefix := object.get(options, "transport_prefix", "")

deny contains violation if {
	startswith(input.package.path, domain_prefix)

	some imp in input.imports
	startswith(imp.path, transport_prefix)

	violation := {
		"message": sprintf("domain package must not import transport package %q", [imp.path]),
		"position": imp.position,
		"rule": "domain_boundary",
	}
}
```

Config:

```yaml
options:
  domain_boundary:
    domain_prefix: example.com/app/internal/domain
    transport_prefix: example.com/app/internal/transport
```

For richer package rules, start from the bundled `architecture/importboundaries` and `architecture/layers` policies.

## Example: migration or deprecation rule

Migration rules are a strong fit for regolint because teams can roll them out incrementally with options and `nolint` exceptions.

```rego
package regolint.rules.migration.oldclient

options := object.get(object.get(input, "rule_options", {}), "oldclient", {})
forbidden_imports := object.get(options, "forbidden_imports", [])

deny contains violation if {
	some imp in input.imports
	imp.path in forbidden_imports

	violation := {
		"message": sprintf("%q is deprecated; use example.com/project/newclient", [imp.path]),
		"position": imp.position,
		"rule": "oldclient",
	}
}
```

Config:

```yaml
options:
  oldclient:
    forbidden_imports:
      - example.com/project/oldclient
```

## Verification workflow

Before publishing a policy:

1. Run focused OPA tests:

   ```bash
   opa test policies/<category>/<rule>.rego policies/<category>/<rule>_test.rego -v
   ```

2. Run the full policy suite:

   ```bash
   opa test ./policies -v
   ```

3. Run regolint in debug dry-run mode on real code:

   ```bash
   regolint --debug --dry-run ./...
   ```

4. Verify:
   - expected violations appear
   - expected non-violations stay clean
   - messages are actionable
   - source positions are useful
   - options are documented and have safe defaults
