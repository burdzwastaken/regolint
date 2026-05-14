package regolint.rules.imports.exptostd

metadata := {
	"id": "exptostd",
	"severity": "warning",
	"description": "Checks for golang.org/x/exp packages that moved to the standard library",
}

stdlib_replacements := {
	"golang.org/x/exp/slices": "slices",
	"golang.org/x/exp/maps": "maps",
	"golang.org/x/exp/cmp": "cmp",
}

deny contains violation if {
	some imp in input.imports
	replacement := stdlib_replacements[imp.path]

	violation := {
		"message": sprintf("Import '%s' can be replaced with standard library package '%s'", [imp.path, replacement]),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
