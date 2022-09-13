package builtin.pipeline.EXTRA_INDEX_URL

import data.lib.pipeline

__rego_metadata__ := {
	"id": "EXTRA_INDEX_URL",
	"avd_id": "AVD-PIPELINE-0001",
	"title": " Using extra-index-url",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Dependency confusion is a common attack, which happens when ci systems or developers confuses between internal packages and external packages which has the same name or one that's very similiar. In that case an attacker can publish a malicious package with the same name as your private package and at some point someone might confuse and pull the malicious one. The --extra-index-url flag works in a way that might install external packages instead of private if their version is higher. It is recommended to use the flag --index-url while installing and also avoid having internal packages in the same name as external ones.",
	"recommended_actions": "Change the --extra-index-url flag to --index-url",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Looking for --extra-index-url flag
deny[result] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	pipeline.contains_pip_install_with_extra_index_url_flag(script)

	result = {
		"msg": sprintf("Avoid using pip install with --extra-index-url flag in job '%s', step '%v'", [input.jobs[i].name, pipeline.get_step_name(input.jobs[i].steps[j], j)]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
