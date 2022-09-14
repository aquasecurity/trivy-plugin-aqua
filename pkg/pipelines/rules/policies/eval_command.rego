package builtin.pipeline.EVAL_COMMAND

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0004",
	"avd_id": "AVD-PIPELINE-0004",
	"title": "Using eval command",
	"severity": "LOW",
	"type": "Pipeline Yaml Security Check",
	"description": "Evaluate command in pipeline(s).",
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
		"msg": sprintf("Consider removing eval command from job '%s' step '%v'", [input.jobs[i].name, pipeline.get_step_name(input.jobs[i].steps[j], j)]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
