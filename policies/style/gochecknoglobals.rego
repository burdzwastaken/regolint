package regolint.rules.style.gochecknoglobals

metadata := {
	"id": "gochecknoglobals",
	"severity": "warning",
	"description": "Checks for package-level variables",
}

deny contains violation if {
	some v in input.variables

	violation := {
		"message": sprintf("Package-level variable '%s' is not allowed", [v.name]),
		"position": v.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
