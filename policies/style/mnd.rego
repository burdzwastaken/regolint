package regolint.rules.style.mnd

metadata := {
	"id": "mnd",
	"severity": "info",
	"description": "Checks for magic number literals in function bodies",
}

numeric_kinds := {"int", "float", "imag"}

allowed_numbers := {"-1", "0", "1", "2", "4", "8", "10", "30", "0.0", "1.0", "2.0"}

normalized(value) := trimmed if {
	trimmed := trim_suffix(value, "i")
}

allowed_number(value) if normalized(value) in allowed_numbers

deny contains violation if {
	some lit in input.literals
	lit.kind in numeric_kinds
	not allowed_number(lit.value)

	violation := {
		"message": sprintf("Magic number literal '%s' should be named", [lit.value]),
		"position": lit.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
