package regolint.rules.context.fatcontext

metadata := {
	"id": "fatcontext",
	"severity": "warning",
	"description": "Checks for context derivation inside range loops",
}

context_deriver(call) if {
	call.package == "context"
	call.function in {"WithCancel", "WithDeadline", "WithTimeout", "WithValue"}
}

inside_loop(call, loop) if {
	call.in_function == loop.in_function
	call.position.line >= loop.position.line
	call.position.line <= loop.end_line
}

deny contains violation if {
	some call in input.calls
	not object.get(call, "in_func_lit", false)
	context_deriver(call)

	some loop in input.range_loops
	inside_loop(call, loop)

	violation := {
		"message": sprintf("Avoid deriving context with context.%s inside range loops", [call.function]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
