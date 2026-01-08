package regolint.rules.security.credentials

metadata := {
	"id": "SEC001",
	"severity": "error",
	"description": "Prevents hardcoded credentials",
}

sensitive_patterns := [
	"password", "passwd", "secret", "token", "apikey",
	"api_key", "private_key", "credential", "auth",
]

deny contains violation if {
	some v in input.constants

	name_lower := lower(v.name)
	some pattern in sensitive_patterns
	contains(name_lower, pattern)

	violation := {
		"message": sprintf("Possible hardcoded credential in constant '%s'", [v.name]),
		"position": v.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some v in input.variables
	v.in_function == ""

	name_lower := lower(v.name)
	some pattern in sensitive_patterns
	contains(name_lower, pattern)

	violation := {
		"message": sprintf("Possible hardcoded credential in package variable '%s'", [v.name]),
		"position": v.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
