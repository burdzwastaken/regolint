package regolint.rules.test.thelper

metadata := {
	"id": "thelper",
	"severity": "warning",
	"description": "Checks test helper functions call t.Helper",
}

testing_param(fn) := param if {
	some param in fn.parameters
	param.type == "*testing.T"
	param.name != ""
}

helper_name(name) if contains(lower(name), "helper")

helper_name(name) if startswith(lower(name), "assert")

helper_name(name) if startswith(lower(name), "require")

helper_name(name) if startswith(lower(name), "check")

helper_call(fn, param) if {
	some call in input.calls
	call.in_function == fn.name
	call.receiver == param.name
	call.function == "Helper"
}

deny contains violation if {
	some fn in input.functions
	not fn.is_test
	helper_name(fn.name)
	param := testing_param(fn)
	not helper_call(fn, param)

	violation := {
		"message": sprintf("Test helper function '%s' should call %s.Helper()", [fn.name, param.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
