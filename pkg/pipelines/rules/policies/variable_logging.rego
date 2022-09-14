package builtin.pipeline.VARIABLES_LOGGING

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0003",
	"avd_id": "AVD-PIPELINE-0003",
	"title": "Echo of variables",
	"severity": "LOW",
	"type": "Pipeline Yaml Security Check",
	"description": "Avoid printing variables. These contain sensitive data, secrets, credentials, and keys. printing them would result in them exposed and printed in plain text. In addition, avoid printing untrusted input that can be manipulated by attacker.",
	"recommended_actions": "Avoid printing variables",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for variable logs
deny[result] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	pipeline.contains_log_functions(script)
	pipeline.contains_variables(script)
	result := {
		"msg": sprintf("Consider removing variable printing from job '%s', step '%v'", [input.jobs[i].name, pipeline.get_step_name(input.jobs[i].steps[j], j)]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
