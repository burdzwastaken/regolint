package regolint.rules.style.errname

metadata := {
	"id": "errname",
	"severity": "warning",
	"description": "Checks error names follow Go conventions",
}

sentinel_error(v) if {
	v.is_exported
	startswith(v.name, "Err") == false
	is_error_value(v)
}

is_error_value(v) if v.type == "error"

is_error_value(v) if startswith(v.value, "errors.New(")

is_error_value(v) if startswith(v.value, "fmt.Errorf(")

error_type(typ) if {
	some fn in input.functions
	fn.receiver == typ.name
	fn.name == "Error"
}

error_type(typ) if {
	some fn in input.functions
	fn.receiver == sprintf("*%s", [typ.name])
	fn.name == "Error"
}

deny contains violation if {
	some v in input.variables
	sentinel_error(v)

	violation := {
		"message": sprintf("Sentinel error '%s' should be named ErrXxx", [v.name]),
		"position": v.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some typ in input.types
	typ.is_exported
	error_type(typ)
	not endswith(typ.name, "Error")

	violation := {
		"message": sprintf("Error type '%s' should be named XxxError", [typ.name]),
		"position": typ.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
