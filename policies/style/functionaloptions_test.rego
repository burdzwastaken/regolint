package regolint.rules.style.functionaloptions_test

import data.regolint.rules.style.functionaloptions

test_inactive_without_configuration if {
	violations := functionaloptions.deny with input as {"functions": [{
		"name": "NewClient",
		"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_detects_constructor_with_too_many_parameters if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"max_parameters": 2}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
	violations[_].rule == "functionaloptions"
}

test_allows_variadic_option_parameter if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"max_parameters": 2}},
		"functions": [{
			"name": "NewClient",
			"parameters": [
				{"type": "context.Context"},
				{"type": "string"},
				{"type": "...Option", "is_variadic": true},
			],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_ignores_non_constructor_prefix if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"max_parameters": 2}},
		"functions": [{
			"name": "BuildClient",
			"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_uses_custom_constructor_prefix if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {
			"max_parameters": 2,
			"constructor_prefixes": ["Build"],
		}},
		"functions": [{
			"name": "BuildClient",
			"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_allows_configured_function if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {
			"max_parameters": 2,
			"allowed_functions": ["NewClient"],
		}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_detects_legacy_configuration if {
	violations := functionaloptions.deny with input as {
		"functional_options_max_parameters": 2,
		"functions": [{
			"name": "NewClient",
			"parameters": [{"type": "string"}, {"type": "int"}, {"type": "bool"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_detects_missing_option_application if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"require_option_application": true}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"name": "opts", "type": "...Option", "is_variadic": true}],
			"position": {"line": 10},
		}],
		"calls": [],
		"range_loops": [],
	}
	count(violations) == 1
	violations[_].message == "NewClient accepts variadic options but no option application was detected"
}

test_allows_direct_option_application_loop if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"require_option_application": true}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"name": "opts", "type": "...Option", "is_variadic": true}],
			"position": {"line": 10},
		}],
		"range_loops": [{
			"source": "opts",
			"value": "opt",
			"in_function": "NewClient",
			"position": {"line": 12},
			"end_line": 14,
		}],
		"calls": [{
			"function": "opt",
			"in_function": "NewClient",
			"position": {"line": 13},
		}],
	}
	count(violations) == 0
}

test_allows_helper_option_forwarding if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"require_option_application": true}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"name": "opts", "type": "...Option", "is_variadic": true}],
			"position": {"line": 10},
		}],
		"calls": [{
			"function": "applyOptions",
			"args": ["client", "opts"],
			"in_function": "NewClient",
			"position": {"line": 12},
		}],
		"range_loops": [],
	}
	count(violations) == 0
}

test_skips_unnamed_variadic_option_application_check if {
	violations := functionaloptions.deny with input as {
		"rule_options": {"functionaloptions": {"require_option_application": true}},
		"functions": [{
			"name": "NewClient",
			"parameters": [{"type": "...Option", "is_variadic": true}],
			"position": {"line": 10},
		}],
		"calls": [],
		"range_loops": [],
	}
	count(violations) == 0
}
