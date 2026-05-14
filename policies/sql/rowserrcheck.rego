package regolint.rules.sql.rowserrcheck

metadata := {
	"id": "rowserrcheck",
	"severity": "warning",
	"description": "Checks that sql.Rows.Err is checked",
}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

has_rows_err(acquire) if {
	some err in input.resource_errs
	err.in_function == acquire.in_function
	err.target == acquire.target
	err.is_checked
	before(acquire, err)
	not reacquired_between(acquire, err)
}

reacquired_between(acquire, err) if {
	some next in input.resource_acquires
	next.in_function == acquire.in_function
	next.target == acquire.target
	next.position != acquire.position
	before(acquire, next)
	before(next, err)
}

deny contains violation if {
	some acquire in input.resource_acquires
	acquire.kind == "sql_rows"
	not has_rows_err(acquire)

	violation := {
		"message": sprintf("Rows from '%s' must have Err checked", [acquire.target]),
		"position": acquire.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
