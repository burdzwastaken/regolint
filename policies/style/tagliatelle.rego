package regolint.rules.style.tagliatelle

metadata := {
	"id": "tagliatelle",
	"severity": "warning",
	"description": "Checks struct tag naming conventions",
}

checked_tags := {"json", "yaml"}

tag_value(tags, tag_name) := value if {
	part := split(tags, " ")[_]
	prefix := sprintf("%s:\"", [tag_name])
	startswith(part, prefix)
	value_with_options := split(trim_prefix(part, prefix), "\"")[0]
	value := split(value_with_options, ",")[0]
}

ignored_tag_value(value) if value == ""

ignored_tag_value(value) if value == "-"

valid_tag_name(value) if regex.match(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`, value)

valid_tag_name(value) if startswith(value, "$")

deny contains violation if {
	some typ in input.types
	typ.kind == "struct"

	some field in typ.fields
	tags := object.get(field, "tags", "")

	some tag_name in checked_tags
	value := tag_value(tags, tag_name)
	not ignored_tag_value(value)
	not valid_tag_name(value)

	violation := {
		"message": sprintf("Struct field '%s.%s' has %s tag '%s' that should be snake_case", [typ.name, field.name, tag_name, value]),
		"position": field.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
