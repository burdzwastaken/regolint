package regolint.rules.comment.dupword

metadata := {
	"id": "dupword",
	"severity": "info",
	"description": "Checks for duplicate consecutive words",
}

word(text, idx) := lower(trim(split(text, " ")[idx], "\t\n\r .,;:!?()[]{}\"'`"))

has_duplicate_word(text) if {
	words := split(text, " ")
	some idx
	words[idx]
	next := idx + 1
	words[next]
	w := word(text, idx)
	w != ""
	not startswith(w, "%")
	w == word(text, next)
}

text_item contains {"text": comment.text, "kind": "comment", "position": comment.position} if {
	some comment in input.comments
}

text_item contains {"text": lit.value, "kind": "string literal", "position": lit.position} if {
	some lit in input.literals
	lit.kind == "string"
}

deny contains violation if {
	some item in text_item
	has_duplicate_word(item.text)

	violation := {
		"message": sprintf("Duplicate word in %s", [item.kind]),
		"position": item.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
