package builtin.pipeline.ID6

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ID6",
	"avd_id": "AVD-ID-6",
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

# Check for untrusted inputs that are not inside env variables in a job
deny[msg] {
	fields := pipeline.get_job_fields(input.jobs[i])
	pipeline.contains_untrusted_inputs(fields[j])
	msg := {
		"msg": fields[j],
		"startline": input.jobs[i].file_reference.start_ref.line,
		"endline": input.jobs[i].file_reference.end_ref.line,
	}
}

# Check for untrusted inputs that are not inside env variables in a job
deny[msg] {
	fields := pipeline.get_step_fields(input.jobs[i].steps[j])
	pipeline.contains_untrusted_inputs(fields[k])
	msg := {
		"msg": fields[k],
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
