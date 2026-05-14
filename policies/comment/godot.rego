package regolint.rules.comment.godot

metadata := {
	"id": "godot",
	"severity": "info",
	"description": "Checks that comments end in a period",
}

terminal_punctuation := {".", "!", "?"}

ignored_comment(text) if startswith(text, "nolint")

ignored_comment(text) if startswith(text, "go:")

ignored_comment(text) if startswith(text, "line ")

ignored_comment(text) if regex.match(`https?://\S+$`, text)

has_terminal_punctuation(text) if {
	some mark in terminal_punctuation
	endswith(text, mark)
}

deny contains violation if {
	some comment in input.comments
	not ignored_comment(comment.text)
	not has_terminal_punctuation(comment.text)

	violation := {
		"message": "Comment should end in a period",
		"position": comment.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
