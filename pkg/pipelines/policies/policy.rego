package main

__rego_metadata__ := {
	"id": "ID1",
	"avd_id": "AVD-ID-1",
	"title": "Pipeline misconfigurations",
	"severity": "MEDIUM",
	"type": "pipeline misconfiguration",
	"description": "ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false",
	"recommended_actions": "Disable the mounting of service account secret token by setting automountServiceAccountToken to false",
	"url": "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#serviceaccount-admission-controller",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

contains_untrusted_inputs(string) = result {
	untrusted_inputs_regex_patterns := [
		`github\.event\.issue\.title`,
		`github\.event\.issue\.body`,
		`github\.event\.pull_request\.title`,
		`github\.event\.pull_request\.body`,
		`github\.event\.comment\.body`,
		`github\.event\.review\.body`,
		`github\.event\.review_comment\.body`,
		`github\.event\.pages\.[^.}]*\.page_name`,
		`github\.event\.commits\.[^.}]*\.message`,
		`github\.event\.head_commit\.message`,
		`github\.event\.head_commit\.author\.email`,
		`github\.event\.head_commit\.author\.name`,
		`github\.event\.commits\.[^.}]*\.author\.email`,
		`github\.event\.commits\.[^.}]*\.author\.name`,
		`github\.event\.pull_request\.head\.ref`,
		`github\.event\.pull_request\.head\.label`,
		`github\.event\.pull_request\.head\.repo\.default_branch`,
		`github\.head_ref`,
	]

	result := count({x |
		variable_wrapped_untrusted_inputs_regex_patterns := concat("", [`\${{\s*`, untrusted_inputs_regex_patterns[x], `\s*}}`])
		regex.match(variable_wrapped_untrusted_inputs_regex_patterns, lower(string))
	}) > 0
}

contains_variables(string) = result {
	variable_regex_pattern := [`\${{\s*[^}]*\s*}}`, `\$`]
	result := regex.match(variable_regex_pattern[_], lower(string))
}

contains_log_functions(string) = result {
	log_functions_regex_patterns := [
		`console\.log\(`,
		`console\.info\(`,
		`console\.error\(`,
		`console\.warn\(`,
		`console\.dir\(`,
		`console\.time\(`,
		`console\.timeEnd\(`,
		`console\.trace\(`,
		`console\.assert\(`,
		`process\.stdout\.write\(`,
		`echo`,
		`print\(`,
		`logging\.info\(`,
		`logging\.warning\(`,
		`logging\.error\(`,
		`logging\.critical\(`,
		`logging\.exception\(`,
		`logging\.log\(`,
	]

	result := count({x |
		regex.match(log_functions_regex_patterns[x], lower(string))
	}) > 0
}

contains_ref_value(val) {
	regex.match(`\${{\s*github\.event\.pull_request\.head\.sha\s*}}`, lower(val))
}

get_job_fields(job) = fields {
	inputValues := [val | val := job.inputs[_].value]
	conditionStatements := [cond | cond := job.conditions[_].statement]
	fields := array.concat(
		array.concat(
			[job.name],
			inputValues,
		),
		conditionStatements,
	)
}

# If step.type != "task", then the next function with the same name will be called
get_step_fields(step) = fields {
	step.type == "task"
	inputValues := [val | val := step.task.inputs[_].value]
	conditionStatements := [cond | cond := step.conditions[_].statement]
	fields := array.concat(array.concat([step.name, step.task.name], conditionStatements), inputValues)
}

get_step_fields(step) = fields {
	step.type == "shell"
	conditionStatements := [cond | cond := step.conditions[_].statement]
	fields := array.concat([step.name, step.shell.script], conditionStatements)
}

get_all_envs[envs] {
	jobEnvs := [env | input.jobs[k].environment_variables != null; env := input.jobs[k].environment_variables]
	stepEnvs := [env | input.jobs[i].steps[j].environment_variables != null; env := input.jobs[i].steps[j].environment_variables]
	envs := array.concat(jobEnvs, stepEnvs)
}

persist_credentials_passing_check(task) {
	task.inputs
	i := task.inputs[x]
	i.name == "persist-credentials"
	i.value == false
}

# Check for untrusted inputs that are not inside env variables in a job
deny[msg] {
	fields := get_job_fields(input.jobs[i])
	contains_untrusted_inputs(fields[j])
	msg := {
		"id": "ERROR_UNTRUSTED_INPUT_NO_ENV",
		"line": fields[j],
		"start_line": input.jobs[i].file_reference.start_ref.line,
		"end_line": input.jobs[i].file_reference.end_ref.line,
	}
}

# Check for untrusted inputs that are not inside env variables in a job
deny[msg] {
	fields := get_step_fields(input.jobs[i].steps[j])
	contains_untrusted_inputs(fields[k])
	msg := {
		"id": "ERROR_UNTRUSTED_INPUT_NO_ENV",
		"line": fields[k],
		"start_line": input.jobs[i].steps[j].file_reference.start_ref.line,
		"end_line": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}

# Check for untrusted inputs that are inside env variables
deny[msg] {
	envs := get_all_envs[_]
	[path, value] := walk(envs[i].environment_variables)
	count(path) == 1
	contains_untrusted_inputs(value)
	msg := {
		"id": "ERROR_UNTRUSTED_INPUT_USAGE",
		"line": value,
		"start_line": envs[i].file_reference.start_ref.line,
		"end_line": envs[i].file_reference.end_ref.line,
	}
}

# Pin actions to a full length commit SHA
deny[msg] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.version_type != "commit"
	msg := {
		"id": "ERROR_ACTION_PINNED_VERSION",
		"line": sprintf("%v@%v", [
			input.jobs[i].steps[j].task.name,
			input.jobs[i].steps[j].task.version,
		]),
		"start_line": input.jobs[i].steps[j].file_reference.start_ref.line,
		"end_line": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}

# Check for variable logs
deny[msg] {
	input.jobs[i].steps[j].type == "shell"
	script := input.jobs[i].steps[j].shell.script

	contains_log_functions(script)
	contains_variables(script)
	msg := {
		"id": "ERROR_VARIABLES_LOGGING",
		"line": script,
		"start_line": input.jobs[i].steps[j].file_reference.start_ref.line,
		"end_line": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}

# Check for checkout action with pull request target for 
deny[msg] {
	input.triggers.triggers[a].event == "pull_request_target"

	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.name == "actions/checkout"
	input.jobs[i].steps[j].task.inputs[k].name == "ref"

	contains_ref_value(input.jobs[i].steps[j].task.inputs[k].value)

	msg := {
		"id": "ERROR_CHECKOUT_WITH_PR_TARGET",
		"line": "pull_request_target",
		"start_line": input.triggers.triggers[a].file_reference.start_ref.line,
		"end_line": input.triggers.triggers[a].file_reference.end_ref.line,
		"index": input.jobs[i].steps[j].file_reference.start_ref.line,
	}
}

# Check for checkout action with persist credentials
deny[msg] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.name == "actions/checkout"
	not persist_credentials_passing_check(input.jobs[i].steps[j].task)

	msg := {
		"id": "ERROR_PERSIST_CREDENTIALS",
		"line": sprintf("%v", [input.jobs[i].steps[j].file_reference.start_ref.line]),
		"start_line": input.jobs[i].steps[j].file_reference.start_ref.line,
		"end_line": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
