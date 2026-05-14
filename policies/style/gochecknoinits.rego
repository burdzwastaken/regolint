package regolint.rules.style.gochecknoinits

metadata := {
	"id": "gochecknoinits",
	"severity": "warning",
	"description": "Checks for init functions",
}

deny contains violation if {
	some fn in input.functions
	fn.name == "init"

	violation := {
		"message": "init functions are not allowed",
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
