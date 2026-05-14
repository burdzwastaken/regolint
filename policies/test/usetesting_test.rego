package regolint.rules.test.usetesting_test

import data.regolint.rules.test.usetesting

test_detects_os_temp_dir_in_test_function if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "is_test": true, "parameters": [{"name": "t", "type": "*testing.T"}], "position": {"line": 3}}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "TempDir", "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
	violations[_].rule == "usetesting"
}

test_detects_os_mkdir_temp_empty_dir if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "MkdirTemp", "args": ["\"\"", "\"prefix\""], "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
}

test_detects_ioutil_temp_file_empty_dir if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "io/ioutil"}],
		"calls": [{"package": "ioutil", "function": "TempFile", "args": ["\"\"", "\"prefix\""], "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
}

test_detects_os_setenv if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "Setenv", "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
}

test_allows_non_test_function_without_testing_param if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "build", "parameters": []}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "TempDir", "in_function": "build", "position": {"line": 4}}],
	}
	count(violations) == 0
}

test_allows_non_empty_temp_dir if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "MkdirTemp", "args": ["base", "\"prefix\""], "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 0
}

test_detects_aliased_os_import if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "os", "alias": "stdos"}],
		"calls": [{"package": "stdos", "function": "Setenv", "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
}

test_allows_shadowed_os_without_import if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"calls": [{"package": "os", "function": "Setenv", "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 0
}

test_detects_raw_empty_dir if {
	violations := usetesting.deny with input as {
		"functions": [{"name": "TestThing", "parameters": [{"name": "t", "type": "*testing.T"}]}],
		"imports": [{"path": "os"}],
		"calls": [{"package": "os", "function": "MkdirTemp", "args": ["``", "\"prefix\""], "in_function": "TestThing", "position": {"line": 4}}],
	}
	count(violations) == 1
}
