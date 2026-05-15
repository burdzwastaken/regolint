package regolint.rules.style.builderchain_test

import data.regolint.rules.style.builderchain

test_inactive_without_configuration if {
	violations := builderchain.deny with input as {"functions": [{
		"name": "WithTimeout",
		"receiver": "*ClientBuilder",
		"returns": [],
		"position": {"line": 10},
	}]}
	count(violations) == 0
}

test_detects_chain_method_without_builder_return if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {"types": ["ClientBuilder"]}},
		"functions": [{
			"name": "WithTimeout",
			"receiver": "*ClientBuilder",
			"returns": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
	violations[_].rule == "builderchain"
}

test_allows_pointer_builder_return if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {"types": ["ClientBuilder"]}},
		"functions": [{
			"name": "WithTimeout",
			"receiver": "*ClientBuilder",
			"returns": [{"type": "*ClientBuilder"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_allows_value_builder_return_when_pointer_not_required if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {"types": ["ClientBuilder"]}},
		"functions": [{
			"name": "WithTimeout",
			"receiver": "ClientBuilder",
			"returns": [{"type": "ClientBuilder"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_detects_value_return_when_pointer_required if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {
			"types": ["ClientBuilder"],
			"require_pointer_return": true,
		}},
		"functions": [{
			"name": "WithTimeout",
			"receiver": "*ClientBuilder",
			"returns": [{"type": "ClientBuilder"}],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_uses_custom_method_prefix if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {
			"types": ["ClientBuilder"],
			"method_prefixes": ["Use"],
		}},
		"functions": [{
			"name": "UseTimeout",
			"receiver": "*ClientBuilder",
			"returns": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}

test_allows_configured_method if {
	violations := builderchain.deny with input as {
		"rule_options": {"builderchain": {
			"types": ["ClientBuilder"],
			"allowed_methods": ["WithTimeout"],
		}},
		"functions": [{
			"name": "WithTimeout",
			"receiver": "*ClientBuilder",
			"returns": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 0
}

test_detects_legacy_configuration if {
	violations := builderchain.deny with input as {
		"builder_chain_types": ["ClientBuilder"],
		"functions": [{
			"name": "WithTimeout",
			"receiver": "*ClientBuilder",
			"returns": [],
			"position": {"line": 10},
		}],
	}
	count(violations) == 1
}
