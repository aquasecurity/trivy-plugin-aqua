package builtin.pipeline.ID8

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID8",
	"avd_id": "AVD-ID-8",
	"title": "echo of variables",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Avoid printing variables. These contain sensitive data, secrets, credentials, and keys. printing them would result in them exposed and printed in plain text. In addition, avoid printing untrusted input that can be manipulated by attacker, like for example, github.event.comment.body.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for variable logs
deny[msg] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	pipeline.contains_log_functions(script)
	pipeline.contains_variables(script)
	msg := {
		"msg": script,
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
