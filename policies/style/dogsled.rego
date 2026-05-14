package regolint.rules.style.dogsled

metadata := {
	"id": "dogsled",
	"severity": "warning",
	"description": "Checks assignments with too many blank identifiers",
	"max_blank_identifiers": 2,
}

deny contains violation if {
	some assignment in input.blank_assignments
	assignment.blank_count > metadata.max_blank_identifiers

	violation := {
		"message": sprintf("Assignment has %d blank identifiers, exceeding maximum of %d", [assignment.blank_count, metadata.max_blank_identifiers]),
		"position": assignment.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
