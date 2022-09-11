package builtin.pipeline.INSECURE_FETCHING

import data.lib.pipeline

__rego_metadata__ := {
	"id": "INSECURE_FETCHING",
	"avd_id": "AVD-PIPELINE-0009",
	"title": "Insecure fetching",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Using 'insecure' or 'skip certificate' flags when fetching files and packages in build is exposing you to the threat of 'man-in-the-middle' that may poison your build without you noticing because the certificate validation, which checks if the source is trusted, is disabled.",
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

	pipeline.contains_insecure_fetching_commands(script)

	result = {
		"msg": sprintf("Avoid using usecured fetching commands in job '%s', step '%s'", [input.jobs[i].name, input.jobs[i].steps[j].name]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
