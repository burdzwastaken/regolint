package regolint.rules.errors.nilnil

metadata := {
	"id": "nilnil",
	"severity": "warning",
	"description": "Checks for returning nil, nil from functions with multiple nillable results",
}

nillable_type(type_name) if type_name == "error"

nillable_type(type_name) if startswith(type_name, "*")

nillable_type(type_name) if startswith(type_name, "[]")

nillable_type(type_name) if startswith(type_name, "map[")

nillable_type(type_name) if startswith(type_name, "chan ")

nillable_type(type_name) if startswith(type_name, "<-chan ")

nillable_type(type_name) if startswith(type_name, "func(")

nillable_type(type_name) if type_name == "interface{}"

nillable_type(type_name) if type_name == "any"

all_results_nil(ret) if {
	count(ret.results) >= 2
	count([result | some result in ret.results; result == "nil"]) == count(ret.results)
}

all_declared_returns_nillable(fn) if {
	count(fn.returns) == count([ret | some ret in fn.returns; nillable_type(ret.type)])
}

deny contains violation if {
	some fn in input.functions
	count(fn.returns) >= 2
	all_declared_returns_nillable(fn)

	some ret in input.returns
	ret.function == fn.name
	object.get(ret, "receiver", "") == object.get(fn, "receiver", "")
	all_results_nil(ret)

	violation := {
		"message": sprintf("Function '%s' returns nil for all result values", [fn.name]),
		"position": ret.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
