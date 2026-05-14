package regolint.rules.style.lll

metadata := {
	"id": "lll",
	"severity": "info",
	"description": "Checks for long lines",
	"max_length": 120,
}

deny contains violation if {
	some line in input.lines
	line.length > metadata.max_length

	violation := {
		"message": sprintf("Line is %d bytes long, exceeding maximum of %d", [line.length, metadata.max_length]),
		"position": line.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
