package regolint.rules.style.inamedparam_test

import data.regolint.rules.style.inamedparam

test_detects_unnamed_interface_parameter if {
	violations := inamedparam.deny with input as {"types": [{
		"name": "Repository",
		"kind": "interface",
		"methods": [{
			"name": "Get",
			"parameters": [{"type": "string"}],
		}],
		"position": {"line": 3},
	}]}
	count(violations) == 1
	violations[_].rule == "inamedparam"
}

test_allows_named_interface_parameter if {
	violations := inamedparam.deny with input as {"types": [{
		"name": "Repository",
		"kind": "interface",
		"methods": [{
			"name": "Get",
			"parameters": [{"name": "id", "type": "string"}],
		}],
		"position": {"line": 3},
	}]}
	count(violations) == 0
}
