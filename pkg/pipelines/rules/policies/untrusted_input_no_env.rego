package builtin.pipeline.UNTRUSTED_INPUT_NO_ENV

import data.lib.pipeline

__rego_metadata__ := {
	"id": "UNTRUSTED_INPUT_NO_ENV",
	"avd_id": "AVD-PIPELINE-0006",
	"title": "Potentially untrusted input - environment variable",
	"severity": "HIGH",
	"type": "Pipeline Yaml Security Check",
	"description": "When defining environment variable inside step that runs a script, the variable is evaluated inside the shell, and as such can be exploited by script injection. The recommendation is to use an intermediate env variable, which is kept in memory as a variable and it's evaluation isn't happening in the same shell where the job runs, so the risk for script injection reduces.",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Check for untrusted inputs that are not inside env variables in a job
deny[result] {
	fields := pipeline.get_job_fields(input.jobs[i])
	pipeline.contains_untrusted_inputs(fields[j])
	result := {
		"msg": fields[j],
		"startline": input.jobs[i].file_reference.start_ref.line,
	}
}

# Check for untrusted inputs that are not inside env variables in a step
deny[result] {
	fields := pipeline.get_step_fields(input.jobs[i].steps[j])
	pipeline.contains_untrusted_inputs(fields[k])
	result := {
		"msg": sprintf("Consider using an intermediate environment variable instead of defining it in the '%s' step shell", [input.jobs[i].steps[j]]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}
