package regolint.rules.style.embeddedstructfieldcheck

metadata := {
	"id": "embeddedstructfieldcheck",
	"severity": "warning",
	"description": "Checks that embedded struct fields appear before regular fields",
}

before(left, right) if left.position.line < right.position.line

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

regular_field_before_embedded(typ, embedded) if {
	some field in typ.fields
	not field.is_embedded
	before(field, embedded)
}

deny contains violation if {
	some typ in input.types
	typ.kind == "struct"

	some field in typ.fields
	field.is_embedded
	regular_field_before_embedded(typ, field)

	violation := {
		"message": sprintf("Embedded field '%s.%s' should appear before regular fields", [typ.name, field.name]),
		"position": field.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
