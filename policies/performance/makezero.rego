package regolint.rules.performance.makezero

metadata := {
	"id": "makezero",
	"severity": "warning",
	"description": "Checks for slices made with non-zero length before append",
}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

non_zero_len(arg) if {
	arg != ""
	arg != "0"
}

deny contains violation if {
	some make_slice in input.make_slices
	non_zero_len(make_slice.len_arg)

	some append_call in input.appends
	append_call.in_function == make_slice.in_function
	append_call.target == make_slice.target
	append_call.source == make_slice.target
	before(make_slice, append_call)

	violation := {
		"message": sprintf("Use make with zero length and capacity when appending to slice '%s'", [make_slice.target]),
		"position": make_slice.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
