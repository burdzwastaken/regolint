package regolint.rules.style.nolintlint

metadata := {
	"id": "nolintlint",
	"severity": "warning",
	"description": "Checks nolint directives for rule specificity",
}

deny contains violation if {
	some directive in input.nolints
	count(object.get(directive, "rules", [])) == 0

	violation := {
		"message": "nolint directive should specify at least one rule",
		"position": {"line": directive.line},
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
