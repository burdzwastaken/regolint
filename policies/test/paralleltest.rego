package regolint.rules.test.paralleltest

metadata := {
	"id": "paralleltest",
	"severity": "warning",
	"description": "Checks test functions call t.Parallel",
}

testing_param(fn) := param if {
	some param in fn.parameters
	param.type == "*testing.T"
	param.name != ""
}

is_test_entrypoint(fn) if {
	fn.is_test
	startswith(fn.name, "Test")
}

parallel_call(fn, param) if {
	some call in input.calls
	call.in_function == fn.name
	not object.get(call, "in_func_lit", false)
	call.receiver == param.name
	call.function == "Parallel"
}

deny contains violation if {
	some fn in input.functions
	is_test_entrypoint(fn)
	param := testing_param(fn)
	not parallel_call(fn, param)

	violation := {
		"message": sprintf("Test function '%s' should call %s.Parallel()", [fn.name, param.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
