package regolint.rules.sql.sqlclosecheck

metadata := {
	"id": "sqlclosecheck",
	"severity": "warning",
	"description": "Checks that SQL rows and statements are closed",
}

close_required_kinds := {"sql_rows", "sql_stmt"}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

has_close(acquire) if {
	some close in input.resource_closes
	close.in_function == acquire.in_function
	close.target == acquire.target
	before(acquire, close)
	not reacquired_between(acquire, close)
}

reacquired_between(acquire, close) if {
	some next in input.resource_acquires
	next.in_function == acquire.in_function
	next.target == acquire.target
	next.position != acquire.position
	before(acquire, next)
	before(next, close)
}

deny contains violation if {
	some acquire in input.resource_acquires
	acquire.kind in close_required_kinds
	not has_close(acquire)

	violation := {
		"message": sprintf("SQL resource '%s' must be closed", [acquire.target]),
		"position": acquire.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
