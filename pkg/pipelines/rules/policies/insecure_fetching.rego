package builtin.pipeline.ID5

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID5",
	"avd_id": "AVD-ID-5",
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
		"msg": script,
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
