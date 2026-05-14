package regolint.rules.style.nakedret

metadata := {
	"id": "nakedret",
	"severity": "warning",
	"description": "Checks for naked returns in functions with named return values",
}

has_named_return(fn) if {
	some ret in fn.returns
	ret.name != ""
}

deny contains violation if {
	some fn in input.functions
	fn.has_naked_ret
	has_named_return(fn)

	violation := {
		"message": sprintf("Function '%s' uses naked return", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
