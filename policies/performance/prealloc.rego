package regolint.rules.performance.prealloc

metadata := {
	"id": "prealloc",
	"severity": "info",
	"description": "Checks slices appended inside range loops without capacity preallocation",
}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

inside_loop(item, loop) if {
	item.in_function == loop.in_function
	item.position.line >= loop.position.line
	item.position.line <= loop.end_line
}

zero_len(arg) if arg == "0"

deny contains violation if {
	some make_slice in input.make_slices
	make_slice.target != ""
	zero_len(make_slice.len_arg)
	not make_slice.has_cap

	some loop in input.range_loops
	loop.in_function == make_slice.in_function
	before(make_slice, loop)

	some append_call in input.appends
	append_call.target == make_slice.target
	append_call.source == make_slice.target
	inside_loop(append_call, loop)

	violation := {
		"message": sprintf("Preallocate capacity for slice '%s' before appending inside range loop", [make_slice.target]),
		"position": make_slice.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
