package regolint.rules.performance.mirror

metadata := {
	"id": "mirror",
	"severity": "info",
	"description": "Checks for bytes/strings package calls on mirrored argument types",
}

mirrored_functions := {"Contains", "ContainsAny", "ContainsRune", "Count", "EqualFold", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexRune", "LastIndex", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "Trim", "TrimLeft", "TrimPrefix", "TrimRight", "TrimSpace", "TrimSuffix"}

string_like(arg) if startswith(arg, "string(...)")

bytes_like(arg) if startswith(arg, "[]byte(...)")

deny contains violation if {
	some call in input.calls
	call.package == "bytes"
	call.function in mirrored_functions
	count(call.args) > 0
	bytes_like(call.args[0])

	violation := {
		"message": sprintf("Use strings.%s instead of bytes.%s when converting a string to []byte", [call.function, call.function]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some call in input.calls
	call.package == "strings"
	call.function in mirrored_functions
	count(call.args) > 0
	string_like(call.args[0])

	violation := {
		"message": sprintf("Use bytes.%s instead of strings.%s when converting []byte to string", [call.function, call.function]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
