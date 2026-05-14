package regolint.rules.performance.perfsprint

metadata := {
	"id": "perfsprint",
	"severity": "info",
	"description": "Checks for simple fmt.Sprintf calls that can use faster formatting helpers",
}

simple_sprintf_replacement := {
	"\"%s\"": "fmt.Sprint",
	"\"%v\"": "fmt.Sprint",
	"\"%d\"": "strconv.Itoa or fmt.Sprint",
	"\"%t\"": "strconv.FormatBool or fmt.Sprint",
}

deny contains violation if {
	some call in input.calls
	call.package == "fmt"
	call.function == "Sprintf"
	count(call.args) == 2
	replacement := simple_sprintf_replacement[call.args[0]]

	violation := {
		"message": sprintf("Use %s instead of fmt.Sprintf with simple format %s", [replacement, call.args[0]]),
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}

deny contains violation if {
	some call in input.calls
	call.package == "fmt"
	call.function == "Sprint"
	count(call.args) == 1
	startswith(call.args[0], "fmt.Sprintf(...)")

	violation := {
		"message": "Avoid wrapping fmt.Sprintf with fmt.Sprint",
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
