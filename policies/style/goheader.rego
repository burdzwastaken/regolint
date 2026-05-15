package regolint.rules.style.goheader

metadata := {
	"id": "goheader",
	"severity": "warning",
	"description": "Checks source file headers against a configured pattern",
}

goheader_options := object.get(object.get(input, "rule_options", {}), "goheader", {})

required_pattern := object.get(goheader_options, "required_pattern", object.get(input, "required_header_pattern", ""))

first_comment_line := min([comment.position.line | some comment in input.comments])

first_comment(comment) if {
	comment.position.line == first_comment_line
	object.get(comment, "is_first_line", true)
}

missing_header if {
	required_pattern != ""
	count(object.get(input, "comments", [])) == 0
}

invalid_header(comment) if {
	required_pattern != ""
	first_comment(comment)
	comment.position.line > 5
}

invalid_header(comment) if {
	required_pattern != ""
	first_comment(comment)
	not regex.match(required_pattern, comment.text)
}

deny contains violation if {
	missing_header

	violation := {
		"message": "Missing required file header",
		"position": {"file": input.file_path, "line": 1, "column": 1},
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some comment in input.comments
	invalid_header(comment)

	violation := {
		"message": "File header does not match required pattern",
		"position": comment.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
