package regolint.rules.style.forcetypeassert

metadata := {
	"id": "forcetypeassert",
	"severity": "warning",
	"description": "Checks unchecked type assertions",
}

deny contains violation if {
	some assertion in input.type_assertions
	assertion.asserted_type != ""
	not assertion.is_comma_ok

	violation := {
		"message": sprintf("Type assertion %s.(%s) should use comma-ok form", [assertion.expr, assertion.asserted_type]),
		"position": assertion.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
