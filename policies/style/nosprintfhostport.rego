package regolint.rules.style.nosprintfhostport

metadata := {
	"id": "nosprintfhostport",
	"severity": "warning",
	"description": "Checks for fmt.Sprintf host:port formatting instead of net.JoinHostPort",
}

host_port_formats := {"\"%s:%s\"", "\"%s:%d\"", "\"%s:%v\"", "\"%v:%v\""}

host_arg(arg) if regex.match(`(?i)(^|[._-])(host|hostname|addr|address|listen_addr|bind_addr)($|[._-])`, arg)

host_arg(arg) if regex.match(`(?i)(host|hostname|addr|address)`, arg)

port_arg(arg) if regex.match(`(?i)(^|[._-])port($|[._-])`, arg)

port_arg(arg) if lower(arg) == "port"

deny contains violation if {
	some call in input.calls
	call.package == "fmt"
	call.function == "Sprintf"
	count(call.args) >= 3
	call.args[0] in host_port_formats
	host_arg(call.args[1])
	port_arg(call.args[2])

	violation := {
		"message": "Use net.JoinHostPort instead of fmt.Sprintf to build host:port strings",
		"position": call.position,
		"rule": metadata.id,
		"severity": metadata.severity,
	}
}
