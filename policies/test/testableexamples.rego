package regolint.rules.test.testableexamples

metadata := {
	"id": "testableexamples",
	"severity": "warning",
	"description": "Checks examples include Output comments",
}

example_function(fn) if startswith(fn.name, "Example")

example_end_line(fn) := (fn.position.line + fn.line_count) - 1

output_comment_for(fn) if {
	some comment in input.comments
	comment.position.line >= fn.position.line
	comment.position.line <= example_end_line(fn)
	startswith(comment.text, "Output:")
}

output_comment_for(fn) if {
	some comment in input.comments
	comment.position.line >= fn.position.line
	comment.position.line <= example_end_line(fn)
	startswith(comment.text, "Unordered output:")
}

deny contains violation if {
	some fn in input.functions
	example_function(fn)
	not output_comment_for(fn)

	violation := {
		"message": sprintf("Example function '%s' should include an Output comment", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
