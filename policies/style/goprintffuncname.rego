package regolint.rules.style.goprintffuncname

metadata := {
	"id": "goprintffuncname",
	"severity": "warning",
	"description": "Checks printf-like function names end with f",
}

printf_like(fn) if {
	count(fn.parameters) >= 2
	format_param := fn.parameters[count(fn.parameters) - 2]
	args_param := fn.parameters[count(fn.parameters) - 1]
	format_param.type == "string"
	variadic_any(args_param.type)
}

variadic_any(type_name) if type_name == "...any"

variadic_any(type_name) if type_name == "...interface{}"

deny contains violation if {
	some fn in input.functions
	printf_like(fn)
	not endswith(lower(fn.name), "f")

	violation := {
		"message": sprintf("Printf-like function '%s' should end with f", [fn.name]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
