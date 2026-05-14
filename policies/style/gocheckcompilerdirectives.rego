package regolint.rules.style.gocheckcompilerdirectives

metadata := {
	"id": "gocheckcompilerdirectives",
	"severity": "warning",
	"description": "Checks malformed compiler directives",
}

known_directives := {
	"go:build",
	"go:generate",
	"go:embed",
	"go:linkname",
	"go:noescape",
	"go:nosplit",
	"go:noinline",
	"go:norace",
	"go:uintptrescapes",
	"go:wasmimport",
	"go:wasmexport",
	"go:debug",
	"go:binary-only-package",
}

has_known_directive_prefix(text) if {
	some directive in known_directives
	text == directive
}

has_known_directive_prefix(text) if {
	some directive in known_directives
	startswith(text, sprintf("%s ", [directive]))
}

malformed_directive(comment) if {
	startswith(object.get(comment, "raw", ""), "//go:")
	startswith(comment.text, "go:")
	not has_known_directive_prefix(comment.text)
}

malformed_directive(comment) if {
	startswith(object.get(comment, "raw", ""), "//go:")
	comment.text == "go:generate"
}

malformed_directive(comment) if {
	startswith(object.get(comment, "raw", ""), "//go:")
	comment.text == "go:build"
}

deny contains violation if {
	some comment in input.comments
	malformed_directive(comment)

	violation := {
		"message": sprintf("Malformed compiler directive '%s'", [comment.text]),
		"position": comment.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
