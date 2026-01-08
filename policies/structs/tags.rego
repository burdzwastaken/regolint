package regolint.rules.structs.tags

metadata := {
	"id": "TAG001",
	"severity": "warning",
	"description": "Ensures exported struct fields have required tags",
}

required_tags := ["json"]

deny contains violation if {
	some t in input.types
	t.kind == "struct"
	t.is_exported

	some field in t.fields
	field.is_exported
	not field.is_embedded

	some tag in required_tags
	not contains(field.tags, concat("", [tag, ":"]))

	violation := {
		"message": sprintf("Exported field '%s.%s' missing required '%s' tag", [t.name, field.name, tag]),
		"position": field.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
