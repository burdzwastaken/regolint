package regolint.rules.test.testpackage

metadata := {
	"id": "testpackage",
	"severity": "warning",
	"description": "Checks that test files use an external _test package",
}

deny contains violation if {
	endswith(input.file_path, "_test.go")
	not endswith(input.package.name, "_test")

	violation := {
		"message": sprintf("Test file should use external package '%s_test'", [input.package.name]),
		"position": {"file": input.file_path, "line": 1, "column": 1},
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
