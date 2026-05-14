package regolint.rules.style.canonicalheader

metadata := {
	"id": "canonicalheader",
	"severity": "warning",
	"description": "Checks HTTP header literals use canonical MIME header keys",
}

canonical_headers := {
	"accept": "Accept",
	"authorization": "Authorization",
	"cache-control": "Cache-Control",
	"content-encoding": "Content-Encoding",
	"content-length": "Content-Length",
	"content-type": "Content-Type",
	"if-match": "If-Match",
	"if-none-match": "If-None-Match",
	"user-agent": "User-Agent",
}

quoted_string(value) := unquoted if {
	startswith(value, "\"")
	endswith(value, "\"")
	unquoted := trim(value, "\"")
}

header_item contains {"value": quoted_string(lit.value), "position": lit.position} if {
	some lit in input.literals
	lit.kind == "string"
}

header_item contains {"value": quoted_string(constant.value), "position": constant.position} if {
	some constant in input.constants
	constant.value != ""
}

header_item contains {"value": quoted_string(variable.value), "position": variable.position} if {
	some variable in input.variables
	variable.value != ""
}

deny contains violation if {
	some item in header_item
	canonical := canonical_headers[lower(item.value)]
	item.value != canonical

	violation := {
		"message": sprintf("HTTP header %q should be canonicalized as %q", [item.value, canonical]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
