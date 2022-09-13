package builtin.pipeline.HTTP_USAGE

import data.lib.pipeline

__rego_metadata__ := {
	"id": "HTTP_USAGE",
	"avd_id": "AVD-PIPELINE-0011",
	"title": "HTTP usage instead of HTTPS",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Using HTTP protocol when reaching sites is highly not recommended due to its insecurity and lack of certificate validation. Use HTTPS protocol instead",
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

	pipeline.contains_http_fetching(script)

	result = {
		"msg": sprintf("Avoid fetching from usecured resources (using http) in job '%s', step '%v'", [input.jobs[i].name, pipeline.get_step_name(input.jobs[i].steps[j], j)]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
