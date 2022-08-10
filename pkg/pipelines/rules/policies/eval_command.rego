package builtin.pipeline.EVAL_COMMAND

import data.lib.pipeline

__rego_metadata__ := {
	"id": "EVAL_COMMAND",
	"avd_id": "",
	"title": "eval command",
	"severity": "LOW",
	"type": "Pipeline Yaml Security Check",
	"description": "Evaluate command in pipeline(s)",
	"recommended_actions": "Avoid using evaluate command during the pipeline",
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
		"msg": sprintf("Consider removing eval command from job %s step %s", [input.jobs[i].name, input.jobs[i].steps[j].name]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
