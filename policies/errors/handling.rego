package regolint.rules.errors.handling

metadata := {
	"id": "ERR001",
	"severity": "warning",
	"description": "Checks for proper error handling patterns",
}

deny contains violation if {
	some fn in input.functions
	fn.is_exported

	some ret in fn.returns
	ret.type == "error"

	calls := [c | some c in input.calls; c.in_function == fn.name]

	has_error_return := count([c |
		some c in calls
		c.function == "New"
		c.package == "errors"
	]) > 0

	has_error_wrap := count([c |
		some c in calls
		c.package == "fmt"
		c.function == "Errorf"
	]) > 0

	has_error_return
	not has_error_wrap

	violation := {
		"message": sprintf("Function '%s' creates errors without wrapping context", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
