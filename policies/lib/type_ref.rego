package regolint.lib.type_ref

children(node) := children if {
	children := [child |
		some field in ["elem", "key", "value"]
		child := object.get(node, field, {})
		object.get(child, "kind", "") != ""
	]
}

matches(ref, type_name) if ref.type == type_name

matches(ref, type_name) if object.get(ref, "type_identity", "") == type_name

matches(ref, type_name) if object.get(ref, "identity", "") == type_name

matches(ref, type_name) if object.get(ref, "display", "") == type_name

matches(ref, type_name) if {
	object.get(ref, "package_path", "") != ""
	sprintf("%s.%s", [ref.package_path, ref.name]) == type_name
}

pattern_matches(ref, pattern) if regex.match(pattern, ref.type)

pattern_matches(ref, pattern) if regex.match(pattern, object.get(ref, "type_identity", ""))

pattern_matches(ref, pattern) if regex.match(pattern, object.get(ref, "identity", ""))

pattern_matches(ref, pattern) if regex.match(pattern, object.get(ref, "display", ""))

pattern_matches(ref, pattern) if regex.match(pattern, object.get(ref, "package_path", ""))

is_named(ref, package_path, name) if {
	object.get(ref, "kind", "") == "named"
	object.get(ref, "package_path", "") == package_path
	object.get(ref, "name", "") == name
}

exposes(ref, forbidden_types, forbidden_patterns, allowed_types) if {
	forbidden_candidate(ref, forbidden_types, forbidden_patterns)
	not allowed_candidate(ref, allowed_types)
}

exposes(ref, forbidden_types, forbidden_patterns, allowed_types) if {
	root := object.get(ref, "type_ref", {})
	node_exposes(root, forbidden_types, forbidden_patterns, allowed_types)
}

exposes(ref, forbidden_types, forbidden_patterns, allowed_types) if {
	root := object.get(ref, "type_ref", {})
	some child in children(root)
	node_exposes(child, forbidden_types, forbidden_patterns, allowed_types)
}

exposes(ref, forbidden_types, forbidden_patterns, allowed_types) if {
	root := object.get(ref, "type_ref", {})
	some child in children(root)
	some grandchild in children(child)
	node_exposes(grandchild, forbidden_types, forbidden_patterns, allowed_types)
}

exposes(ref, forbidden_types, forbidden_patterns, allowed_types) if {
	root := object.get(ref, "type_ref", {})
	some child in children(root)
	some grandchild in children(child)
	some great_grandchild in children(grandchild)
	node_exposes(great_grandchild, forbidden_types, forbidden_patterns, allowed_types)
}

node_exposes(node, forbidden_types, forbidden_patterns, allowed_types) if {
	object.get(node, "kind", "") != ""
	forbidden_candidate(node, forbidden_types, forbidden_patterns)
	not allowed_candidate(node, allowed_types)
}

forbidden_candidate(candidate, forbidden_types, _) if {
	some type_name in forbidden_types
	matches(candidate, type_name)
}

forbidden_candidate(candidate, _, forbidden_patterns) if {
	some pattern in forbidden_patterns
	pattern_matches(candidate, pattern)
}

allowed_candidate(candidate, allowed_types) if {
	some type_name in allowed_types
	matches(candidate, type_name)
}
