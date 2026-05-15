package regolint.rules.style.constructorinterfaces

metadata := {
	"id": "constructorinterfaces",
	"severity": "warning",
	"description": "Checks configured constructors accept interface dependencies",
}

constructorinterfaces_options := object.get(object.get(input, "rule_options", {}), "constructorinterfaces", {})

constructor_prefixes := object.get(constructorinterfaces_options, "constructor_prefixes", object.get(input, "constructor_interfaces_constructor_prefixes", ["New"]))

allowed_functions := object.get(constructorinterfaces_options, "allowed_functions", object.get(input, "constructor_interfaces_allowed_functions", []))

dependency_rules := object.get(constructorinterfaces_options, "dependency_rules", object.get(input, "constructor_interface_rules", []))

require_exported := object.get(constructorinterfaces_options, "require_exported", object.get(input, "constructor_interfaces_require_exported", true))

configured if count(dependency_rules) > 0

constructor(fn) if {
	some prefix in constructor_prefixes
	startswith(fn.name, prefix)
}

exported_constructor(_) if not require_exported

exported_constructor(fn) if fn.is_exported

allowed_function(fn) if fn.name in allowed_functions

rule_parameter_names(rule) := object.get(rule, "parameter_names", [])

rule_allowed_interfaces(rule) := object.get(rule, "allowed_interfaces", [])

rule_forbidden_types(rule) := object.get(rule, "forbidden_types", [])

rule_forbidden_type_patterns(rule) := object.get(rule, "forbidden_type_patterns", [])

rule_message(rule, fn, param) := msg if {
	msg := object.get(rule, "message", sprintf("%s should accept an interface for %s instead of %s", [fn.name, param.name, param.type]))
}

target_parameter(rule, _) if count(rule_parameter_names(rule)) == 0

target_parameter(rule, param) if param.name in rule_parameter_names(rule)

allowed_interface(rule, param) if {
	some type_name in rule_allowed_interfaces(rule)
	parameter_type_matches(param, type_name)
}

forbidden_dependency(rule, param) if {
	some type_name in rule_forbidden_types(rule)
	parameter_type_matches(param, type_name)
}

forbidden_dependency(rule, param) if {
	some pattern in rule_forbidden_type_patterns(rule)
	parameter_type_pattern_matches(param, pattern)
}

parameter_type_matches(param, type_name) if param.type == type_name

parameter_type_matches(param, type_name) if object.get(param, "type_identity", "") == type_name

parameter_type_pattern_matches(param, pattern) if regex.match(pattern, param.type)

parameter_type_pattern_matches(param, pattern) if regex.match(pattern, object.get(param, "type_identity", ""))

deny contains violation if {
	configured
	some fn in input.functions
	constructor(fn)
	exported_constructor(fn)
	not allowed_function(fn)

	some rule in dependency_rules
	some param in fn.parameters
	target_parameter(rule, param)
	forbidden_dependency(rule, param)
	not allowed_interface(rule, param)

	violation := {
		"message": rule_message(rule, fn, param),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
