package regolint.rules.style.iotamixing

metadata := {
	"id": "iotamixing",
	"severity": "warning",
	"description": "Checks const blocks that mix iota and non-iota values",
}

iota_const(block_id) if {
	some constant in input.constants
	constant.block_id == block_id
	constant.uses_iota
}

non_iota_const(block_id) if {
	some constant in input.constants
	constant.block_id == block_id
	not constant.uses_iota
}

first_non_iota(block_id) := constant if {
	constant := input.constants[_]
	constant.block_id == block_id
	not constant.uses_iota
	constant.position.line == min([other.position.line |
		some other in input.constants
		other.block_id == block_id
		not other.uses_iota
	])
}

deny contains violation if {
	some group in input.decl_groups
	group.kind == "const"
	group.is_grouped
	iota_const(group.block_id)
	non_iota_const(group.block_id)
	constant := first_non_iota(group.block_id)

	violation := {
		"message": sprintf("Const block mixes iota and non-iota constant '%s'", [constant.name]),
		"position": constant.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
