package regolint.rules.errors.nilerr

metadata := {
	"id": "nilerr",
	"severity": "warning",
	"description": "Checks for returning nil error values after checking an error is not nil",
}

error_return_index(fn, idx) if {
	fn.returns[idx].type == "error"
}

same_function(fn, if_stmt) if {
	if_stmt.function == fn.name
	object.get(if_stmt, "receiver", "") == object.get(fn, "receiver", "")
}

return_matches_signature(fn, ret) if count(ret.results) == count(fn.returns)

nil_error_return(fn, ret) if {
	some idx
	error_return_index(fn, idx)
	ret.results[idx] == "nil"
}

deny contains violation if {
	some fn in input.functions
	some if_stmt in input.ifs
	if_stmt.is_err_not_nil
	same_function(fn, if_stmt)

	some ret in if_stmt.returns
	not ret.is_naked
	return_matches_signature(fn, ret)
	nil_error_return(fn, ret)

	violation := {
		"message": sprintf("Function '%s' returns nil error after checking %s is not nil", [fn.name, if_stmt.error_var]),
		"position": ret.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
