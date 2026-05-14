package regolint.rules.style.nonamedreturns

metadata := {
	"id": "nonamedreturns",
	"severity": "warning",
	"description": "Checks for named return values",
}

deny contains violation if {
	some fn in input.functions
	some ret in fn.returns
	ret.name != ""

	violation := {
		"message": sprintf("Function '%s' has named return values", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
