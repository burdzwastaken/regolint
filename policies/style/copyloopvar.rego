package regolint.rules.style.copyloopvar

metadata := {
	"id": "copyloopvar",
	"severity": "warning",
	"description": "Checks for redundant copies of range loop variables",
}

deny contains violation if {
	some copy in input.loop_var_copies

	violation := {
		"message": sprintf("Range loop %s variable '%s' is copied to itself", [copy.kind, copy.variable]),
		"position": copy.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
