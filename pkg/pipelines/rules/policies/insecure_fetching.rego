package builtin.pipeline.INSECURE_FETCHING

import data.lib.pipeline

__rego_metadata__ := {
	"id": "INSECURE_FETCHING",
	"avd_id": "AVD-PIPELINE-0009",
	"title": "insecure fetching",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Unencrypted fetching request",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Looking for fetching commands
deny[result] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	pipeline.contains_fetching_commands(script)

	result = {
		"msg": sprintf("Avoid using usecured fetching commands in job '%s', step '%s'", [input.jobs[i].name, input.jobs[i].steps[j].name]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
