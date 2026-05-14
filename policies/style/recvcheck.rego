package regolint.rules.style.recvcheck

metadata := {
	"id": "recvcheck",
	"severity": "warning",
	"description": "Checks for inconsistent receiver types",
}

receiver_type(receiver) := trim_prefix(receiver, "*")

has_pointer_receiver(type_name) if {
	some fn in input.functions
	fn.receiver == sprintf("*%s", [type_name])
}

has_value_receiver(type_name) if {
	some fn in input.functions
	fn.receiver == type_name
}

receiver_type_names contains receiver_type(fn.receiver) if {
	some fn in input.functions
	fn.receiver != ""
}

deny contains violation if {
	some type_name in receiver_type_names
	has_pointer_receiver(type_name)
	has_value_receiver(type_name)

	violation := {
		"message": sprintf("Type '%s' mixes pointer and value receivers", [type_name]),
		"position": [fn.position | some fn in input.functions; receiver_type(fn.receiver) == type_name][0],
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
