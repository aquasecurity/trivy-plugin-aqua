package builtin.pipeline.ID4

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID4",
	"avd_id": "AVD-ID-4",
	"title": "eval command",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "eval command",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Looking for eval command
deny[result] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	pipeline.contains_eval(script)

	result = {
		"msg": script,
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
