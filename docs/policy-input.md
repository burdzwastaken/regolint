# Policy input reference

regolint policies receive structured Go source metadata. Single-file policies receive `CodeContext`; package-wide policies receive `PackageContext`.

## CodeContext schema

| Field                  | Type   | Description                                  |
|------------------------|--------|----------------------------------------------|
| `file_path`            | string | Absolute path to the source file             |
| `module_path`          | string | Go module path                               |
| `package`              | object | Package name, path and doc                   |
| `imports`              | array  | Import declarations                          |
| `functions`            | array  | Function and method declarations             |
| `types`                | array  | Type declarations (struct, interface, alias) |
| `variables`            | array  | Package-level variables                      |
| `constants`            | array  | Constants                                    |
| `lines`                | array  | Source line metadata                         |
| `comments`             | array  | Source comments                              |
| `literals`             | array  | Literal expressions                          |
| `composite_literals`   | array  | Composite literal expressions                |
| `returns`              | array  | Return statements                            |
| `ifs`                  | array  | If statements and direct returns             |
| `type_assertions`      | array  | Type assertion expressions                   |
| `make_slices`          | array  | Slice make expressions assigned to targets   |
| `appends`              | array  | Append calls assigned to targets             |
| `resource_acquires`    | array  | Resource-producing assignments               |
| `resource_closes`      | array  | Resource close calls                         |
| `resource_errs`        | array  | Resource error-check calls                   |
| `subtests`             | array  | Subtest callback metadata                    |
| `range_loops`          | array  | Range loop metadata                          |
| `loop_var_copies`      | array  | Redundant range loop variable copies         |
| `blank_assignments`    | array  | Assignments containing blank identifiers     |
| `decl_groups`          | array  | Top-level declaration groups                 |
| `declarations`         | array  | Top-level declarations in source order       |
| `calls`                | array  | Function and method calls                    |
| `type_usages`          | array  | References to types                          |
| `field_accesses`       | array  | Field access expressions                     |
| `nolints`              | array  | nolint suppression directives                |
| `rule_options`         | object | Configured options keyed by rule             |

## Type reference

### ImportInfo (`input.imports[]`)

| Field      | Type   | Description                                |
|------------|--------|--------------------------------------------|
| `path`     | string | Import path (e.g., `"fmt"`)              |
| `alias`    | string | Import alias if any (e.g., `"_"`)        |
| `position` | object | Source location (`file`, `line`, `column`) |

### FunctionInfo (`input.functions[]`)

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

### ParameterInfo (`input.functions[].parameters[]`, `input.functions[].returns[]`)

| Field           | Type    | Description                                                 |
|-----------------|---------|-------------------------------------------------------------|
| `name`          | string  | Parameter or return value name                              |
| `type`          | string  | Rendered type                                               |
| `type_identity` | string  | Optional semantic type string, or syntactic type fallback   |
| `is_variadic`   | boolean | Optional marker for variadic function parameters            |

### TypeInfo (`input.types[]`)

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

### CommentInfo (`input.comments[]`)

| Field           | Type    | Description                                 |
|-----------------|---------|---------------------------------------------|
| `text`          | string  | Comment text without comment markers        |
| `raw`           | string  | Raw source comment text                     |
| `is_first_line` | boolean | Whether this is the first line of a comment |
| `position`      | object  | Source location (`file`, `line`, `column`)  |

### LineInfo (`input.lines[]`)

| Field      | Type    | Description                                |
|------------|---------|--------------------------------------------|
| `number`   | integer | Source line number                         |
| `length`   | integer | Source line length in bytes                |
| `position` | object  | Source location (`file`, `line`, `column`) |

### LiteralInfo (`input.literals[]`)

| Field         | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `kind`        | string | Literal kind (`int`, `float`, `imag`, `char`, `string`) |
| `value`       | string | Literal source text                                     |
| `in_function` | string | Function containing this literal                        |
| `position`    | object | Source location (`file`, `line`, `column`)              |

### CompositeLiteralInfo (`input.composite_literals[]`)

| Field           | Type   | Description                                               |
|-----------------|--------|-----------------------------------------------------------|
| `type`          | string | Rendered literal type                                     |
| `type_identity` | string | Optional semantic type string, or syntactic type fallback |
| `type_kind`     | string | Optional type kind                                        |
| `fields`        | array  | Optional field names assigned in the literal              |
| `in_function`   | string | Optional function containing this literal                 |
| `position`      | object | Source location (`file`, `line`, `column`)                |

### ReturnInfo (`input.returns[]`)

| Field      | Type    | Description                                |
|------------|---------|--------------------------------------------|
| `function` | string  | Function containing this return statement  |
| `receiver` | string  | Receiver type for method returns           |
| `results`  | array   | Return result expressions as strings       |
| `is_naked` | boolean | Whether this is a bare return statement    |
| `position` | object  | Source location (`file`, `line`, `column`) |

### IfInfo (`input.ifs[]`)

| Field            | Type    | Description                                      |
|------------------|---------|--------------------------------------------------|
| `function`       | string  | Function containing this if statement            |
| `receiver`       | string  | Receiver type for method if statements           |
| `condition`      | string  | If condition expression as a string              |
| `error_var`      | string  | Error variable name from `err != nil` conditions |
| `is_err_not_nil` | boolean | Whether condition contains `<ident> != nil`      |
| `returns`        | array   | Direct return statements in the if body          |
| `position`       | object  | Source location (`file`, `line`, `column`)       |

### TypeAssertInfo (`input.type_assertions[]`)

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

### MakeSliceInfo (`input.make_slices[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Assignment target receiving the slice      |
| `len_arg`     | string  | Length argument passed to `make`           |
| `cap_arg`     | string  | Capacity argument passed to `make`         |
| `has_cap`     | boolean | Whether a capacity argument was provided   |
| `in_function` | string  | Function containing this expression        |
| `position`    | object  | Source location (`file`, `line`, `column`) |

### AppendInfo (`input.appends[]`)

| Field         | Type   | Description                                |
|---------------|--------|--------------------------------------------|
| `target`      | string | Assignment target receiving append result  |
| `source`      | string | First argument passed to `append`          |
| `in_function` | string | Function containing this append call       |
| `position`    | object | Source location (`file`, `line`, `column`) |

### ResourceInfo (`input.resource_acquires[]`)

| Field         | Type   | Description                                             |
|---------------|--------|---------------------------------------------------------|
| `kind`        | string | Resource kind (`http_response`, `sql_rows`, `sql_stmt`) |
| `target`      | string | Assignment target receiving the resource                |
| `source`      | string | Producing call expression                               |
| `in_function` | string | Function containing this acquisition                    |
| `position`    | object | Source location (`file`, `line`, `column`)              |

### ResourceClose (`input.resource_closes[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Closed resource expression                 |
| `is_defer`    | boolean | Whether the close call is deferred         |
| `in_function` | string  | Function containing this close call        |
| `position`    | object  | Source location (`file`, `line`, `column`) |

### ResourceErr (`input.resource_errs[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `target`      | string  | Resource whose `Err` method is called      |
| `is_checked`  | boolean | Whether the error result is checked        |
| `in_function` | string  | Function containing this error check       |
| `position`    | object  | Source location (`file`, `line`, `column`) |

### SubtestInfo (`input.subtests[]`)

| Field          | Type    | Description                                |
|----------------|---------|--------------------------------------------|
| `name`         | string  | Static subtest name when available         |
| `function`     | string  | Parent test function name                  |
| `test_param`   | string  | Subtest `*testing.T` parameter name        |
| `has_parallel` | boolean | Whether subtest calls `t.Parallel()`       |
| `position`     | object  | Source location (`file`, `line`, `column`) |

### RangeLoopInfo (`input.range_loops[]`)

| Field         | Type    | Description                                |
|---------------|---------|--------------------------------------------|
| `key`         | string  | Range key variable name                    |
| `value`       | string  | Range value variable name                  |
| `source`      | string  | Ranged expression                          |
| `in_function` | string  | Function containing this range loop        |
| `end_line`    | integer | Last source line of this range loop body   |
| `position`    | object  | Source location (`file`, `line`, `column`) |

### LoopVarCopyInfo (`input.loop_var_copies[]`)

| Field         | Type   | Description                                |
|---------------|--------|--------------------------------------------|
| `variable`    | string | Copied range variable name                 |
| `kind`        | string | Loop variable kind (`key` or `value`)      |
| `in_function` | string | Function containing this copy              |
| `position`    | object | Source location (`file`, `line`, `column`) |

### BlankAssignInfo (`input.blank_assignments[]`)

| Field         | Type    | Description                                  |
|---------------|---------|----------------------------------------------|
| `blank_count` | integer | Number of blank identifiers on the left side |
| `total_count` | integer | Total left-side expressions                  |
| `in_function` | string  | Function containing this assignment          |
| `position`    | object  | Source location (`file`, `line`, `column`)   |

### DeclGroupInfo (`input.decl_groups[]`)

| Field        | Type    | Description                                         |
|--------------|---------|-----------------------------------------------------|
| `kind`       | string  | Declaration kind (`const`, `import`, `type`, `var`) |
| `count`      | integer | Number of items in the declaration                  |
| `is_grouped` | boolean | Whether the declaration uses grouped form           |
| `block_id`   | integer | File-local declaration group identifier             |
| `position`   | object  | Source location (`file`, `line`, `column`)          |

### DeclInfo (`input.declarations[]`)

| Field      | Type   | Description                                                 |
|------------|--------|-------------------------------------------------------------|
| `kind`     | string | Declaration kind (`import`, `const`, `var`, `type`, `func`) |
| `name`     | string | Declaration name                                            |
| `position` | object | Source location (`file`, `line`, `column`)                  |

### FieldInfo (`input.types[].fields[]`)

| Field           | Type    | Description                                               |
|-----------------|---------|-----------------------------------------------------------|
| `name`          | string  | Field name                                                |
| `type`          | string  | Field type                                                |
| `type_identity` | string  | Optional semantic type string, or syntactic type fallback |
| `tags`          | string  | Struct tags (e.g., `` `json:"foo" ``)                    |
| `is_exported`   | boolean | Whether field is exported                                 |
| `is_embedded`   | boolean | Whether field is an embedded type                         |
| `position`      | object  | Source location                                           |

### VariableInfo (`input.variables[]`, `input.constants[]`)

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

### NolintDirective (`input.nolints[]`)

| Field      | Type    | Description                 |
|------------|---------|-----------------------------|
| `line`     | integer | Directive line              |
| `end_line` | integer | Optional range end line     |
| `rules`    | array   | Suppressed rule IDs         |
| `reason`   | string  | Optional suppression reason |

### CallInfo (`input.calls[]`)

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

### TypeUsageInfo (`input.type_usages[]`)

| Field         | Type   | Description                                     |
|---------------|--------|-------------------------------------------------|
| `type_name`   | string | Name of the type being used                     |
| `package`     | string | Package of the type                             |
| `in_function` | string | Function containing this usage                  |
| `context`     | string | Usage context (e.g., `"parameter"`, `"return"`) |
| `position`    | object | Source location                                 |

### FieldAccessInfo (`input.field_accesses[]`)

| Field         | Type   | Description                     |
|---------------|--------|---------------------------------|
| `field`       | string | Accessed field name             |
| `receiver`    | string | Receiver expression             |
| `type`        | string | Type of the receiver            |
| `in_function` | string | Function containing this access |
| `position`    | object | Source location                 |

## PackageContext schema

| Field                    | Type   | Description                                 |
|--------------------------|--------|---------------------------------------------|
| `module_path`            | string | Go module path                              |
| `package`                | object | Package name, path and doc                  |
| `files`                  | array  | All CodeContext objects in the package      |
| `all_imports`            | array  | Deduplicated imports across all files       |
| `all_functions`          | array  | All functions across all files              |
| `all_types`              | array  | All types across all files                  |
| `all_variables`          | array  | All variables across all files              |
| `all_constants`          | array  | All constants across all files              |
| `all_lines`              | array  | All source lines across all files           |
| `all_comments`           | array  | All comments across all files               |
| `all_literals`           | array  | All literals across all files               |
| `all_composite_literals` | array  | All composite literals across all files     |
| `all_returns`            | array  | All return statements across all files      |
| `all_ifs`                | array  | All if statements across all files          |
| `all_type_assertions`    | array  | All type assertions across all files        |
| `all_make_slices`        | array  | All slice make expressions across all files |
| `all_appends`            | array  | All append calls across all files           |
| `all_resource_acquires`  | array  | All resource acquisitions across all files  |
| `all_resource_closes`    | array  | All resource close calls across all files   |
| `all_resource_errs`      | array  | All resource error checks across all files  |
| `all_subtests`           | array  | All subtests across all files               |
| `all_range_loops`        | array  | All range loops across all files            |
| `all_loop_var_copies`    | array  | All loop variable copies across all files   |
| `all_blank_assignments`  | array  | All blank assignments across all files      |
| `all_decl_groups`        | array  | All declaration groups across all files     |
| `all_declarations`       | array  | All declarations across all files           |
| `all_calls`              | array  | All calls across all files                  |
| `all_type_usages`        | array  | All type usages across all files            |
| `all_field_accesses`     | array  | All field accesses across all files         |
| `rule_options`           | object | Configured options keyed by rule            |

## Custom built-ins

| Built-in                         | Description                           |
|----------------------------------|---------------------------------------|
| `go.matches_pattern(str, regex)` | Check if string matches regex pattern |
| `go.is_exported(name)`           | Check if identifier is exported       |
| `go.is_test_file(filename)`      | Check if file is a test file          |
| `go.package_name(import_path)`   | Extract package name from import path |
