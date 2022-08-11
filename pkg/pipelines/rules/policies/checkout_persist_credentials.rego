package builtin.pipeline.PERSIST_CREDENTIALS

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PERSIST_CREDENTIALS",
	"avd_id": "AVD-ID-2",
	"title": "persist-credentials is true",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "The checkout action stores secrets it uses on disk by default. This can result in leak of sensitive data, because an attacker that gained access to the runner where checkout action run, or injected malicious code to the running workflow will gain access to the secret stored. So it is recommended to set persist-credentials to false, so the action will save it only in memory and there will be less chance for an attacker to steal the secret",
	"recommended_actions": "Add persist-credentials: false to the checkout action",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for checkout action with persist credentials
deny[result] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.name == "actions/checkout"
	not pipeline.persist_credentials_passing_check(input.jobs[i].steps[j].task)

	result := {
		"msg": sprintf("Consider adding persist-credentials: false to the checkout action in job %s inputs", [input.jobs[i].name]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
