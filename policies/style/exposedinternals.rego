package regolint.rules.style.exposedinternals

metadata := {
	"id": "exposedinternals",
	"severity": "warning",
	"description": "Checks exported APIs do not expose configured internal types",
}

exposedinternals_options := object.get(object.get(input, "rule_options", {}), "exposedinternals", {})

forbidden_types := object.get(exposedinternals_options, "forbidden_types", object.get(input, "exposed_internal_types", []))

forbidden_type_patterns := object.get(exposedinternals_options, "forbidden_type_patterns", object.get(input, "exposed_internal_type_patterns", []))

allowed_types := object.get(exposedinternals_options, "allowed_types", object.get(input, "exposed_internal_allowed_types", []))

allowed_functions := object.get(exposedinternals_options, "allowed_functions", object.get(input, "exposed_internal_allowed_functions", []))

check_parameters := object.get(exposedinternals_options, "check_parameters", object.get(input, "exposed_internal_check_parameters", true))

check_returns := object.get(exposedinternals_options, "check_returns", object.get(input, "exposed_internal_check_returns", true))

check_fields := object.get(exposedinternals_options, "check_fields", object.get(input, "exposed_internal_check_fields", true))

configured if count(forbidden_types) > 0

configured if count(forbidden_type_patterns) > 0

allowed_function(fn) if fn.name in allowed_functions

allowed_type(ref) if {
	some type_name in allowed_types
	type_matches(ref, type_name)
}

forbidden_type(ref) if {
	some type_name in forbidden_types
	type_matches(ref, type_name)
}

forbidden_type(ref) if {
	some pattern in forbidden_type_patterns
	type_pattern_matches(ref, pattern)
}

type_matches(ref, type_name) if ref.type == type_name

type_matches(ref, type_name) if object.get(ref, "type_identity", "") == type_name

type_pattern_matches(ref, pattern) if regex.match(pattern, ref.type)

type_pattern_matches(ref, pattern) if regex.match(pattern, object.get(ref, "type_identity", ""))

exposed_internal(ref) if {
	forbidden_type(ref)
	not allowed_type(ref)
}

deny contains violation if {
	configured
	check_parameters
	some fn in input.functions
	fn.is_exported
	not allowed_function(fn)

	some param in fn.parameters
	exposed_internal(param)

	violation := {
		"message": sprintf("%s exposes internal type %s in parameter %s", [fn.name, param.type, param.name]),
		"position": object.get(fn, "position", {}),
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	configured
	check_returns
	some fn in input.functions
	fn.is_exported
	not allowed_function(fn)

	some ret in fn.returns
	exposed_internal(ret)

	violation := {
		"message": sprintf("%s exposes internal type %s in return value", [fn.name, ret.type]),
		"position": object.get(fn, "position", {}),
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	configured
	check_fields
	some typ in input.types
	typ.is_exported

	some field in typ.fields
	field.is_exported
	exposed_internal(field)

	violation := {
		"message": sprintf("%s.%s exposes internal type %s", [typ.name, field.name, field.type]),
		"position": object.get(field, "position", {}),
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
