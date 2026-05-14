package regolint.rules.style.goheader_test

import data.regolint.rules.style.goheader

test_detects_missing_header_when_configured if {
	violations := goheader.deny with input as {"file_path": "main.go", "required_header_pattern": "Copyright"}
	count(violations) == 1
	violations[_].rule == "goheader"
}

test_detects_header_mismatch if {
	violations := goheader.deny with input as {"required_header_pattern": "Copyright", "comments": [{"text": "Package docs.", "position": {"line": 1}}]}
	count(violations) == 1
}

test_allows_matching_header if {
	violations := goheader.deny with input as {"required_header_pattern": "Copyright", "comments": [{"text": "Copyright 2026 Example", "position": {"line": 1}}]}
	count(violations) == 0
}

test_inactive_without_configured_pattern if {
	violations := goheader.deny with input as {"file_path": "main.go", "comments": [{"text": "Package docs.", "position": {"line": 1}}]}
	count(violations) == 0
}

test_allows_multiline_block_header_when_first_line_matches if {
	violations := goheader.deny with input as {"required_header_pattern": "Copyright", "comments": [
		{"text": "Copyright 2026 Example", "is_first_line": true, "position": {"line": 1}},
		{"text": "Licensed under terms.", "is_first_line": false, "position": {"line": 1}},
	]}
	count(violations) == 0
}
