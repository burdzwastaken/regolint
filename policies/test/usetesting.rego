package regolint.rules.test.usetesting

metadata := {
	"id": "usetesting",
	"severity": "warning",
	"description": "Checks test code for standard library helpers that should use testing.T helpers",
}

testing_param(fn) := param if {
	some param in fn.parameters
	param.type == "*testing.T"
	param.name != ""
}

same_function(call, fn) if call.in_function == fn.name

empty_arg(value) if value == "\"\""

empty_arg(value) if value == "``"

imported_as(call, path) if {
	some imp in input.imports
	imp.path == path
	imp.alias == call.package
}

imported_as(call, path) if {
	some imp in input.imports
	imp.path == path
	object.get(imp, "alias", "") == ""
	call.package == package_name(path)
}

package_name("os") := "os"

package_name("io/ioutil") := "ioutil"

temp_dir_helper_call(call) if {
	imported_as(call, "os")
	call.function == "TempDir"
}

temp_dir_helper_call(call) if {
	imported_as(call, "os")
	call.function == "MkdirTemp"
	count(call.args) > 0
	empty_arg(call.args[0])
}

temp_dir_helper_call(call) if {
	imported_as(call, "io/ioutil")
	call.function == "TempDir"
	count(call.args) > 0
	empty_arg(call.args[0])
}

temp_file_helper_call(call) if {
	imported_as(call, "os")
	call.function == "CreateTemp"
	count(call.args) > 0
	empty_arg(call.args[0])
}

temp_file_helper_call(call) if {
	imported_as(call, "io/ioutil")
	call.function == "TempFile"
	count(call.args) > 0
	empty_arg(call.args[0])
}

setenv_call(call) if {
	imported_as(call, "os")
	call.function == "Setenv"
}

deny contains violation if {
	some fn in input.functions
	param := testing_param(fn)
	some call in input.calls
	same_function(call, fn)
	temp_dir_helper_call(call)

	violation := {
		"message": sprintf("Use %s.TempDir() instead of %s.%s in test code", [param.name, call.package, call.function]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some fn in input.functions
	param := testing_param(fn)
	some call in input.calls
	same_function(call, fn)
	temp_file_helper_call(call)

	violation := {
		"message": sprintf("Create temporary files under %s.TempDir() instead of using %s.%s with an empty directory", [param.name, call.package, call.function]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some fn in input.functions
	param := testing_param(fn)
	some call in input.calls
	same_function(call, fn)
	setenv_call(call)

	violation := {
		"message": sprintf("Use %s.Setenv() instead of os.Setenv in test code", [param.name]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
