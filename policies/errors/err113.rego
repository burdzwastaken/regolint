package regolint.rules.errors.err113

metadata := {
	"id": "err113",
	"severity": "warning",
	"description": "Checks for dynamic error creation and non-wrapping formatted errors",
}

format_string(call) := trim(call.args[0], "\"") if {
	count(call.args) > 0
	startswith(call.args[0], "\"")
	endswith(call.args[0], "\"")
}

format_wraps_error(call) if {
	contains(format_string(call), "%w")
}

error_like_arg(arg) if {
	regex.match(`(?i)(^|[._])err(or)?$`, arg)
}

error_like_arg(arg) if {
	regex.match(`(?i)(err|error)$`, arg)
}

has_error_arg(call) if {
	some idx
	idx > 0
	idx < count(call.args)
	error_like_arg(call.args[idx])
}

deny contains violation if {
	some call in input.calls
	call.package == "errors"
	call.function == "New"
	call.in_function != ""

	violation := {
		"message": "Use package-level sentinel errors instead of dynamic errors.New calls",
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some call in input.calls
	call.package == "fmt"
	call.function == "Errorf"
	call.in_function != ""
	has_error_arg(call)
	not format_wraps_error(call)

	violation := {
		"message": "Use %w when formatting errors with fmt.Errorf",
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
