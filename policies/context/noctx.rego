package regolint.rules.context.noctx

metadata := {
	"id": "noctx",
	"severity": "warning",
	"description": "Checks for HTTP requests created without context",
}

deny contains violation if {
	some call in input.calls
	not object.get(call, "in_func_lit", false)
	call.package == "http"
	call.function == "NewRequest"

	violation := {
		"message": "Use http.NewRequestWithContext instead of http.NewRequest",
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
