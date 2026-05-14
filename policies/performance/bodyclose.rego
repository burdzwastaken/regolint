package regolint.rules.performance.bodyclose

metadata := {
	"id": "bodyclose",
	"severity": "warning",
	"description": "Checks that HTTP response bodies are closed",
}

before(left, right) if {
	left.position.line < right.position.line
}

before(left, right) if {
	left.position.line == right.position.line
	left.position.column < right.position.column
}

response_body(target) := sprintf("%s.Body", [target])

has_body_close(acquire) if {
	some close in input.resource_closes
	close.in_function == acquire.in_function
	close.target == response_body(acquire.target)
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
	acquire.kind == "http_response"
	not has_body_close(acquire)

	violation := {
		"message": sprintf("HTTP response body from '%s' must be closed", [acquire.target]),
		"position": acquire.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
