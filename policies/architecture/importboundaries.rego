package regolint.rules.architecture.importboundaries

metadata := {
	"id": "importboundaries",
	"severity": "error",
	"description": "Checks configured package import boundaries",
}

importboundaries_options := object.get(object.get(input, "rule_options", {}), "importboundaries", {})

boundary_rules := object.get(importboundaries_options, "rules", object.get(input, "import_boundary_rules", []))

configured if count(boundary_rules) > 0

package_path := object.get(object.get(input, "package", {}), "path", "")

rule_from(rule) := object.get(rule, "from", "")

rule_forbidden(rule) := object.get(rule, "forbidden", [])

rule_message(rule, imp) := msg if {
	msg := object.get(rule, "message", sprintf("package %q cannot import %q by configured boundary", [package_path, imp.path]))
}

package_matches(rule) if {
	pattern := rule_from(rule)
	pattern != ""
	regex.match(pattern, package_path)
}

import_matches(rule, imp) if {
	some pattern in rule_forbidden(rule)
	regex.match(pattern, imp.path)
}

deny contains violation if {
	configured
	some rule in boundary_rules
	package_matches(rule)

	some imp in input.imports
	import_matches(rule, imp)

	violation := {
		"message": rule_message(rule, imp),
		"position": imp.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
