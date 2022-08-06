package builtin.pipeline.ID2

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID2",
	"avd_id": "AVD-ID-2",
	"title": "persist-credentials is true",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "the checkout action stores secrets it uses on disk by default. This can result in leak of sensitive data, because an attacker that gained access to the runner where checkout action run, or injected malicious code to the running workflow will gain access to the secret stored. So it is recommended to set persist-credentials to false, so the action will save it only in memory and there will be less chance for an attacker to steal the secret.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for checkout action with persist credentials
deny[msg] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.name == "actions/checkout"
	not pipeline.persist_credentials_passing_check(input.jobs[i].steps[j].task)

	msg := {
		"id": "ERROR_PERSIST_CREDENTIALS",
		"line": sprintf("%v", [input.jobs[i].steps[j].file_reference.start_ref.line]),
		"start_line": input.jobs[i].steps[j].file_reference.start_ref.line,
		"end_line": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
