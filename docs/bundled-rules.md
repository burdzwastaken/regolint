# Bundled rules

The `policies/` directory contains bundled policies you can use directly or copy into your project and customize. Some rules are direct structural checks, while others are partial or heuristic approximations of existing Go linters based on the metadata available in `CodeContext` and `PackageContext`.

Status meanings:

- **Full**: Implements the core rule behavior for the metadata regolint exposes.
- **Partial**: Covers common cases, but intentionally omits edge cases that need type information, deeper control flow or whole-program analysis.
- **Heuristic**: Uses syntactic pattern matching and may produce false positives or false negatives in unusual code.

| Category     | Policy                            | Rule ID                     | Status    | Notes                                                  |
|--------------|-----------------------------------|-----------------------------|-----------|--------------------------------------------------------|
| Architecture | `architecture/layers`             | `archlayers`                | Full      | Enforces configured layer import boundaries.           |
| Architecture | `architecture/importboundaries`    | `importboundaries`          | Full      | Checks configured package import boundaries.           |
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
| Style        | `style/builderchain`              | `builderchain`              | Full      | Checks configured builder methods return builder type.  |
| Style        | `style/builderonly`               | `builderonly`               | Full      | Checks configured types use builders for construction.  |
| Style        | `style/canonicalheader`           | `canonicalheader`           | Heuristic | Checks known HTTP header literals.                     |
| Style        | `style/containedctx`              | `containedctx`              | Heuristic | Checks syntactic `context.Context` struct fields.      |
| Style        | `style/constructorinterfaces`     | `constructorinterfaces`     | Partial   | Checks configured constructor dependency types.         |
| Style        | `style/copyloopvar`               | `copyloopvar`               | Partial   | Checks redundant range loop variable copies.           |
| Style        | `style/decorder`                  | `decorder`                  | Full      | Checks top-level declaration order.                    |
| Style        | `style/dogsled`                   | `dogsled`                   | Full      | Checks assignments with too many blank identifiers.    |
| Style        | `style/embeddedstructfieldcheck`  | `embeddedstructfieldcheck`  | Full      | Checks embedded field ordering.                        |
| Style        | `style/errname`                   | `errname`                   | Heuristic | Checks error naming conventions.                       |
| Style        | `style/exposedinternals`          | `exposedinternals`          | Partial   | Checks configured internal types exposed in exported APIs. |
| Style        | `style/forbidigo`                 | `forbidigo`                 | Heuristic | Checks configured forbidden code patterns.             |
| Style        | `style/forcetypeassert`           | `forcetypeassert`           | Partial   | Checks unchecked type assertions.                      |
| Style        | `style/functionaloptions`         | `functionaloptions`         | Full      | Checks configured constructors use functional options.  |
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
