package regolint.rules.style.builderchain

metadata := {
	"id": "builderchain",
	"severity": "warning",
	"description": "Checks configured builder methods return the builder type",
}

builderchain_options := object.get(object.get(input, "rule_options", {}), "builderchain", {})

builder_types := object.get(builderchain_options, "types", object.get(input, "builder_chain_types", []))

method_prefixes := object.get(builderchain_options, "method_prefixes", object.get(input, "builder_chain_method_prefixes", ["With", "Set"]))

allowed_methods := object.get(builderchain_options, "allowed_methods", object.get(input, "builder_chain_allowed_methods", ["Build"]))

require_pointer_return := object.get(builderchain_options, "require_pointer_return", object.get(input, "builder_chain_require_pointer_return", false))

configured if count(builder_types) > 0

receiver_type(receiver) := trim_prefix(receiver, "*")

configured_builder_receiver(receiver) if {
	receiver != ""
	base := receiver_type(receiver)
	some type_name in builder_types
	configured_type_matches(type_name, base)
}

configured_type_matches(type_name, base) if type_name == base

configured_type_matches(type_name, base) if type_name == sprintf("*%s", [base])

configured_type_matches(type_name, base) if endswith(type_name, sprintf(".%s", [base]))

chain_method(fn) if {
	some prefix in method_prefixes
	startswith(fn.name, prefix)
}

allowed_method(fn) if fn.name in allowed_methods

returns_builder(fn) if {
	count(fn.returns) == 1
	ret := fn.returns[0]
	return_matches_receiver(ret, fn.receiver)
}

return_matches_receiver(ret, receiver) if {
	not require_pointer_return
	base := receiver_type(receiver)
	return_type_matches(object.get(ret, "type", ""), base)
}

return_matches_receiver(ret, receiver) if {
	not require_pointer_return
	base := receiver_type(receiver)
	return_type_matches(object.get(ret, "type_identity", ""), base)
}

return_matches_receiver(ret, receiver) if {
	require_pointer_return
	base := receiver_type(receiver)
	object.get(ret, "type", "") == sprintf("*%s", [base])
}

return_matches_receiver(ret, receiver) if {
	require_pointer_return
	base := receiver_type(receiver)
	endswith(object.get(ret, "type_identity", ""), sprintf(".%s", [base]))
	startswith(object.get(ret, "type_identity", ""), "*")
}

return_type_matches(type_name, base) if type_name == base

return_type_matches(type_name, base) if type_name == sprintf("*%s", [base])

return_type_matches(type_name, base) if endswith(type_name, sprintf(".%s", [base]))

deny contains violation if {
	configured
	some fn in input.functions
	configured_builder_receiver(fn.receiver)
	chain_method(fn)
	not allowed_method(fn)
	not returns_builder(fn)

	violation := {
		"message": sprintf("%s should return %s for builder chaining", [fn.name, fn.receiver]),
		"position": fn.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
