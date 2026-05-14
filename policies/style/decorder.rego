package regolint.rules.style.decorder

metadata := {
	"id": "decorder",
	"severity": "warning",
	"description": "Checks top-level declaration order",
}

order := {"import": 0, "const": 1, "var": 2, "type": 3, "func": 4}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

deny contains violation if {
	some earlier in input.declarations
	some later in input.declarations
	before(earlier, later)
	order[earlier.kind] > order[later.kind]

	violation := {
		"message": sprintf("%s declaration '%s' should appear before %s declaration '%s'", [later.kind, later.name, earlier.kind, earlier.name]),
		"position": later.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
