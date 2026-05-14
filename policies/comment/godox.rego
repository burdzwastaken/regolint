package regolint.rules.comment.godox

metadata := {
	"id": "godox",
	"severity": "info",
	"description": "Checks for TODO, FIXME, HACK and BUG comments",
}

markers := {"TODO", "FIXME", "HACK", "BUG"}

deny contains violation if {
	some comment in input.comments
	some marker in markers
	regex.match(sprintf(`(^|[^A-Za-z])%s([^A-Za-z]|$)`, [marker]), upper(comment.text))

	violation := {
		"message": sprintf("Comment contains %s marker", [marker]),
		"position": comment.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
