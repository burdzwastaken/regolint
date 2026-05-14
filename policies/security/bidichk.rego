package regolint.rules.security.bidichk

metadata := {
	"id": "bidichk",
	"severity": "error",
	"description": "Checks for dangerous Unicode bidirectional control characters",
}

bidi_pattern := `[\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]`

contains_bidi(text) if regex.match(bidi_pattern, text)

text_item contains {"kind": "comment", "position": comment.position} if {
	some comment in input.comments
	contains_bidi(comment.text)
}

text_item contains {"kind": "literal", "position": lit.position} if {
	some lit in input.literals
	contains_bidi(lit.value)
}

text_item contains {"kind": "constant value", "position": constant.position} if {
	some constant in input.constants
	contains_bidi(object.get(constant, "value", ""))
}

text_item contains {"kind": "variable value", "position": variable.position} if {
	some variable in input.variables
	contains_bidi(object.get(variable, "value", ""))
}

identifier contains {"kind": "package", "position": {"file": input.file_path, "line": 1, "column": 1}} if {
	contains_bidi(input.package.name)
}

identifier contains {"kind": "function", "position": fn.position} if {
	some fn in input.functions
	contains_bidi(fn.name)
}

identifier contains {"kind": "parameter", "position": fn.position} if {
	some fn in input.functions
	some param in fn.parameters
	contains_bidi(object.get(param, "name", ""))
}

identifier contains {"kind": "return value", "position": fn.position} if {
	some fn in input.functions
	some ret in fn.returns
	contains_bidi(object.get(ret, "name", ""))
}

identifier contains {"kind": "type", "position": typ.position} if {
	some typ in input.types
	contains_bidi(typ.name)
}

identifier contains {"kind": "field", "position": field.position} if {
	some typ in input.types
	some field in typ.fields
	contains_bidi(field.name)
}

identifier contains {"kind": "method", "position": typ.position} if {
	some typ in input.types
	some method in typ.methods
	contains_bidi(method.name)
}

identifier contains {"kind": "variable", "position": variable.position} if {
	some variable in input.variables
	contains_bidi(variable.name)
}

identifier contains {"kind": "constant", "position": constant.position} if {
	some constant in input.constants
	contains_bidi(constant.name)
}

deny contains violation if {
	some item in text_item

	violation := {
		"message": sprintf("%s contains dangerous Unicode bidirectional control characters", [item.kind]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some item in identifier

	violation := {
		"message": sprintf("%s identifier contains dangerous Unicode bidirectional control characters", [item.kind]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
