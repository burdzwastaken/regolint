package regolint.rules.complexity.nestif

metadata := {
	"id": "nestif",
	"severity": "warning",
	"description": "Checks for deeply nested if statements",
	"max_depth": 5,
}

deny contains violation if {
	some fn in input.functions
	fn.max_if_depth > metadata.max_depth

	violation := {
		"message": sprintf("Function '%s' has if nesting depth %d, exceeding maximum of %d", [fn.name, fn.max_if_depth, metadata.max_depth]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
