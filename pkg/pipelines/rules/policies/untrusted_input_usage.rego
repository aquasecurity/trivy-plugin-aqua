package builtin.pipeline.UNTRUSTED_INPUT_USAGE

import data.lib.pipeline

__rego_metadata__ := {
	"id": "PIPELINE-0007",
	"avd_id": "AVD-PIPELINE-0007",
	"title": "Potentially untrusted input - input usage",
	"severity": "LOW",
	"type": "Pipeline Yaml Security Check",
	"description": "GitHub Actions workflows can be triggered by a variety of events. Every workflow trigger is provided with a GitHub context that contains information about the triggering event, such as which user triggered it, the branch name, and other event context details. Some of this event data, like the base repository name, hash value of a changeset, or pull request number, is unlikely to be controlled or used for injection by the user that triggered the event (e.g. a pull request).  However, there is a long list of event context data that might be attacker controlled and should be treated as potentially untrusted input. Developers should carefully handle potentially untrusted input and make sure it doesn't flow into API calls where the data could be interpreted as code.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for untrusted inputs that are inside env variables in steps
deny[result] {
	envs := input.jobs[i].steps[j].environment_variables
	[_, value] := walk(envs.environment_variables)
	pipeline.contains_untrusted_inputs(value)
	result := {
		"msg": sprintf("Consider evaluating user inputs in intermediate environment variables instead of using them right in '%s' job in '%v' step", [input.jobs[i].name, pipeline.get_step_name(input.jobs[i].steps[j], j)]),
		"startline": envs.file_reference.start_ref.line,
	}
}

# Check for untrusted inputs that are inside env variables in jobs
deny[result] {
	envs := input.jobs[i].environment_variables
	[_, value] := walk(envs.environment_variables)
	pipeline.contains_untrusted_inputs(value)
	result := {
		"msg": sprintf("Consider evaluating user inputs in intermediate environment variables instead of using them right in '%s' job", [input.jobs[i].name]),
		"startline": envs.file_reference.start_ref.line,
	}
}