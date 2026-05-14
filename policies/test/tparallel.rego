package regolint.rules.test.tparallel

metadata := {
	"id": "tparallel",
	"severity": "warning",
	"description": "Checks subtests call t.Parallel",
}

subtest_label(subtest) := label if {
	name := object.get(subtest, "name", "")
	name != ""
	label := sprintf("subtest '%s'", [name])
}

subtest_label(subtest) := "subtest" if {
	object.get(subtest, "name", "") == ""
}

deny contains violation if {
	some subtest in input.subtests
	not subtest.has_parallel

	label := subtest_label(subtest)

	violation := {
		"message": sprintf("%s in '%s' should call %s.Parallel()", [label, subtest.function, subtest.test_param]),
		"position": subtest.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
