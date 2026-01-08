package regolint.rules.imports.banned

metadata := {
	"id": "IMP001",
	"severity": "error",
	"description": "Prevents use of banned packages",
}

banned_packages := {"unsafe"}

deny contains violation if {
	some imp in input.imports
	imp.path in banned_packages

	violation := {
		"message": sprintf("Import of banned package '%s' is not allowed", [imp.path]),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
