package builtin.pipeline.ID3

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID3",
	"avd_id": "AVD-ID-3",
	"title": "checkout with pull_request_target",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "pull_request_target gives write permissions to the target repository. While it is good when automating PR labeling, performing chekout or build action can inject your source code in the original repository, instead of running in the merge commit like pull_request trigger. It is recommended to avoid checkout and build when triggering a workflow with pull_request_target.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for checkout action with pull request target for 
deny[msg] {
	input.triggers.triggers[a].event == "pull_request_target"

	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.name == "actions/checkout"
	input.jobs[i].steps[j].task.inputs[k].name == "ref"

	pipeline.contains_ref_value(input.jobs[i].steps[j].task.inputs[k].value)

	msg := {
		"id": "ERROR_CHECKOUT_WITH_PR_TARGET",
		"line": "pull_request_target",
		"start_line": input.triggers.triggers[a].file_reference.start_ref.line,
		"end_line": input.triggers.triggers[a].file_reference.end_ref.line,
		"index": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
