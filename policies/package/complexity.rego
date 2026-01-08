package regolint.rules.package.complexity

metadata := {
	"id": "PKG002",
	"severity": "warning",
	"description": "Checks package-wide complexity metrics",
}

max_complexity := 15
max_function_lines := 50

deny contains violation if {
	some fn in input.all_functions
	fn.complexity > max_complexity

	violation := {
		"message": sprintf("Function '%s' has complexity %d (max %d)", [fn.name, fn.complexity, max_complexity]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
		"fix": {"description": "Consider breaking this function into smaller functions"},
	}
}

deny contains violation if {
	some fn in input.all_functions
	fn.line_count > max_function_lines

	violation := {
		"message": sprintf("Function '%s' has %d lines (max %d)", [fn.name, fn.line_count, max_function_lines]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
		"fix": {"description": "Consider breaking this function into smaller functions"},
	}
}
