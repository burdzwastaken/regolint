package regolint.rules.naming.conventions

metadata := {
	"id": "NAME001",
	"severity": "warning",
	"description": "Enforces naming conventions for types",
}

deny contains violation if {
	some t in input.types
	t.kind == "interface"

	methods := {m.name | some m in t.methods}
	typical_repo_methods := {"Get", "Create", "Update", "Delete", "Find", "List"}
	count(methods & typical_repo_methods) >= 2

	not endswith(t.name, "Repository")
	not endswith(t.name, "Store")
	not endswith(t.name, "Repo")

	violation := {
		"message": sprintf("Interface '%s' appears to be a repository but doesn't follow naming convention", [t.name]),
		"position": t.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some t in input.types
	t.kind == "interface"

	methods := {m.name | some m in t.methods}
	typical_service_methods := {"Execute", "Process", "Handle", "Run", "Do"}
	count(methods & typical_service_methods) >= 1

	not endswith(t.name, "Service")
	not endswith(t.name, "Handler")
	not endswith(t.name, "Processor")
	not endswith(t.name, "er")

	violation := {
		"message": sprintf("Interface '%s' appears to be a service but doesn't follow naming convention", [t.name]),
		"position": t.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
