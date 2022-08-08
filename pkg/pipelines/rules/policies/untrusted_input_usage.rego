package builtin.pipeline.ID7

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID7",
	"avd_id": "AVD-ID-7",
	"title": "Potentially untrusted input",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "GitHub Actions workflows can be triggered by a variety of events. Every workflow trigger is provided with a GitHub context that contains information about the triggering event, such as which user triggered it, the branch name, and other event context details. Some of this event data, like the base repository name, hash value of a changeset, or pull request number, is unlikely to be controlled or used for injection by the user that triggered the event (e.g. a pull request).  However, there is a long list of event context data that might be attacker controlled and should be treated as potentially untrusted input. Developers should carefully handle potentially untrusted input and make sure it doesn't flow into API calls where the data could be interpreted as code.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for untrusted inputs that are inside env variables
deny[msg] {
	envs := pipeline.get_all_envs[_]
	[path, value] := walk(envs[i].environment_variables)
	count(path) == 1
	pipeline.contains_untrusted_inputs(value)
	msg := {
		"msg": value,
		"startline": envs[i].file_reference.start_ref.line,
		"endline": envs[i].file_reference.end_ref.line,
	}
}
