package regolint.rules.style.forbidigo

metadata := {
	"id": "forbidigo",
	"severity": "warning",
	"description": "Checks configured forbidden identifiers, calls and string literals",
}

default_forbidden_identifiers := {"DEBUG", "DebugOnly"}

default_forbidden_calls := {"log.Fatal"}

default_forbidden_strings := {"changeme", "password"}

forbidigo_options := object.get(object.get(input, "rule_options", {}), "forbidigo", {})

configured_forbidden_identifiers := object.get(forbidigo_options, "identifiers", object.get(input, "forbidden_identifiers", []))

configured_forbidden_calls := object.get(forbidigo_options, "calls", object.get(input, "forbidden_calls", []))

configured_forbidden_strings := object.get(forbidigo_options, "strings", object.get(input, "forbidden_strings", []))

forbidden_identifier(name) if name in default_forbidden_identifiers

forbidden_identifier(name) if name in configured_forbidden_identifiers

forbidden_call(name) if name in default_forbidden_calls

forbidden_call(name) if name in configured_forbidden_calls

forbidden_string(value) if value in default_forbidden_strings

forbidden_string(value) if value in configured_forbidden_strings

call_name(call) := name if {
	call.package != ""
	name := sprintf("%s.%s", [call.package, call.function])
}

call_name(call) := name if {
	object.get(call, "package", "") == ""
	call.receiver != ""
	name := sprintf("%s.%s", [call.receiver, call.function])
}

call_name(call) := call.function if {
	object.get(call, "package", "") == ""
	object.get(call, "receiver", "") == ""
}

identifier_item contains {"name": input.package.name, "kind": "package", "position": {"line": 1}} if input.package.name != ""

identifier_item contains {"name": fn.name, "kind": "function", "position": fn.position} if some fn in input.functions

identifier_item contains {"name": param.name, "kind": "parameter", "position": fn.position} if {
	some fn in input.functions
	some param in fn.parameters
	param.name != ""
}

identifier_item contains {"name": ret.name, "kind": "return value", "position": fn.position} if {
	some fn in input.functions
	some ret in fn.returns
	ret.name != ""
}

identifier_item contains {"name": typ.name, "kind": "type", "position": typ.position} if some typ in input.types

identifier_item contains {"name": field.name, "kind": "field", "position": field.position} if {
	some typ in input.types
	some field in typ.fields
	field.name != ""
}

identifier_item contains {"name": method.name, "kind": "method", "position": typ.position} if {
	some typ in input.types
	some method in typ.methods
}

identifier_item contains {"name": variable.name, "kind": "variable", "position": variable.position} if some variable in input.variables

identifier_item contains {"name": constant.name, "kind": "constant", "position": constant.position} if some constant in input.constants

quoted_string(value) := unquoted if {
	startswith(value, "\"")
	endswith(value, "\"")
	unquoted := trim(value, "\"")
}

string_item contains {"value": quoted_string(lit.value), "position": lit.position} if {
	some lit in input.literals
	lit.kind == "string"
}

string_item contains {"value": quoted_string(constant.value), "position": constant.position} if {
	some constant in input.constants
	constant.value != ""
}

string_item contains {"value": quoted_string(variable.value), "position": variable.position} if {
	some variable in input.variables
	variable.value != ""
}

deny contains violation if {
	some item in identifier_item
	forbidden_identifier(item.name)

	violation := {
		"message": sprintf("Forbidden %s identifier %q", [item.kind, item.name]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some call in input.calls
	name := call_name(call)
	forbidden_call(name)

	violation := {
		"message": sprintf("Forbidden call %q", [name]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some item in string_item
	forbidden_string(item.value)

	violation := {
		"message": sprintf("Forbidden string literal %q", [item.value]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
