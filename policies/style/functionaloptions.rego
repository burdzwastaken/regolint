package regolint.rules.style.functionaloptions

metadata := {
	"id": "functionaloptions",
	"severity": "warning",
	"description": "Checks configured constructors use functional options",
}

functionaloptions_options := object.get(object.get(input, "rule_options", {}), "functionaloptions", {})

max_parameters := object.get(functionaloptions_options, "max_parameters", object.get(input, "functional_options_max_parameters", null))

constructor_prefixes := object.get(functionaloptions_options, "constructor_prefixes", object.get(input, "functional_options_constructor_prefixes", ["New"]))

option_suffixes := object.get(functionaloptions_options, "option_suffixes", object.get(input, "functional_options_option_suffixes", ["Option"]))

allowed_functions := object.get(functionaloptions_options, "allowed_functions", object.get(input, "functional_options_allowed_functions", []))

require_option_application := object.get(functionaloptions_options, "require_option_application", object.get(input, "functional_options_require_option_application", false))

configured if max_parameters != null

configured if require_option_application

constructor(fn) if {
	some prefix in constructor_prefixes
	startswith(fn.name, prefix)
}

allowed_function(fn) if fn.name in allowed_functions

non_context_parameters(fn) := params if {
	params := [p | some p in fn.parameters; not context_parameter(p)]
}

context_parameter(p) if p.type == "context.Context"

context_parameter(p) if p.type_identity == "context.Context"

has_variadic_option(fn) if {
	count(fn.parameters) > 0
	last_param := fn.parameters[count(fn.parameters) - 1]
	last_param.is_variadic
	option_parameter(last_param)
}

variadic_option_param(fn) := param if {
	count(fn.parameters) > 0
	param := fn.parameters[count(fn.parameters) - 1]
	param.is_variadic
	param.name != ""
	option_parameter(param)
}

option_parameter(param) if {
	some suffix in option_suffixes
	endswith(param.type, suffix)
}

option_parameter(param) if {
	some suffix in option_suffixes
	endswith(object.get(param, "type_identity", ""), suffix)
}

option_application_detected(fn, param) if direct_option_application(fn, param)

option_application_detected(fn, param) if helper_option_forwarding(fn, param)

direct_option_application(fn, param) if {
	some loop in input.range_loops
	loop.in_function == fn.name
	loop.source == param.name
	loop.value != ""

	some call in input.calls
	call.in_function == fn.name
	not object.get(call, "in_func_lit", false)
	call.function == loop.value
	call.position.line >= loop.position.line
	call.position.line <= loop.end_line
}

helper_option_forwarding(fn, param) if {
	some call in input.calls
	call.in_function == fn.name
	not object.get(call, "in_func_lit", false)
	param.name in call.args
}

deny contains violation if {
	configured
	some fn in input.functions
	constructor(fn)
	not allowed_function(fn)
	params := non_context_parameters(fn)
	count(params) > max_parameters
	not has_variadic_option(fn)

	violation := {
		"message": sprintf("%s has too many constructor parameters; prefer functional options", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	require_option_application
	some fn in input.functions
	constructor(fn)
	not allowed_function(fn)
	param := variadic_option_param(fn)
	not option_application_detected(fn, param)

	violation := {
		"message": sprintf("%s accepts variadic options but no option application was detected", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
