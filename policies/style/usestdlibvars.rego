package regolint.rules.style.usestdlibvars

metadata := {
	"id": "usestdlibvars",
	"severity": "info",
	"description": "Checks for values that should use standard library constants",
}

stdlib_values := {
	"GET": "http.MethodGet",
	"POST": "http.MethodPost",
	"PUT": "http.MethodPut",
	"PATCH": "http.MethodPatch",
	"DELETE": "http.MethodDelete",
	"HEAD": "http.MethodHead",
	"OPTIONS": "http.MethodOptions",
	"CONNECT": "http.MethodConnect",
	"TRACE": "http.MethodTrace",
	"Content-Type": "http.CanonicalHeaderKey(\"Content-Type\")",
	"Accept": "http.CanonicalHeaderKey(\"Accept\")",
	"Authorization": "http.CanonicalHeaderKey(\"Authorization\")",
}

quoted_string(value) := unquoted if {
	startswith(value, "\"")
	endswith(value, "\"")
	unquoted := trim(value, "\"")
}

literal_item contains {"value": quoted_string(lit.value), "position": lit.position} if {
	some lit in input.literals
	lit.kind == "string"
}

literal_item contains {"value": quoted_string(constant.value), "position": constant.position} if {
	some constant in input.constants
	constant.value != ""
}

literal_item contains {"value": quoted_string(variable.value), "position": variable.position} if {
	some variable in input.variables
	variable.value != ""
}

deny contains violation if {
	some item in literal_item
	replacement := stdlib_values[item.value]

	violation := {
		"message": sprintf("Use standard library value '%s' instead of literal %q", [replacement, item.value]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
