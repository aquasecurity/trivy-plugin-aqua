package lib.pipeline

import future.keywords.every


contains_insecure_fetching_commands(string) = result {
	fetching_commands := [
		`curl .*(-[a-zA-Z]*k|--insecure)`,
		`wget .*--no-check-certificate`,
	]

	result := count({x |
		regex.match(fetching_commands[x], lower(string))
	}) > 0
}


contains_http_fetching(string) = result {
	http_regex := [
		`curl.*http:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)`,
		`wget.*http:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)`,
	]

	result := count({x |
		regex.match(http_regex[x], lower(string))
	}) > 0
}

contains_pip_install_with_extra_index_url_flag(string) = result {
	result := regex.match(`.*?pip install .*--extra-index-url .*`, lower(string))
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

contains_eval(string) = result {
	result := regex.match(`^eval `, lower(string))
}

contains_variables(string) = result {
	variable_regex_pattern := [`\${{\s*[^}]*\s*}}`, `\$`]
	result := regex.match(variable_regex_pattern[_], lower(string))
}

contains_log_functions(string) = result {
	log_functions_regex_patterns := [
		`console\..*\(`,
		`process\.stdout\.write\(`,
		`echo`,
		`print\(`,
		`logging\..*\(`,
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

does_job_contain_one_of_tasks(job, regexes) {
	job.steps[i].type == "task"
	regex.match(regexes[_], job.steps[i].task.name)
}

does_job_contain_one_of_shell_commands(job, regexes) {
	job.steps[i].type == "shell"
	r := regexes[_]
	regex.match(r, job.steps[i].shell.script)
}

does_runner_match(job, runner) {
	job.runner.docker_metadata.image == runner
}

does_contain_environment_variable(job, name, regexp) {
	job.environment_variables.environment_variables[name]
	regex.match(regexp, job.environment_variables.environment_variables[name])
}

does_contains_one_of_commands(job, regexes) {
	job.steps[i].type == "shell"
	count({j | regex.match(regexes[j], job.steps[i].shell.script)}) > 0
}

does_task_match(task, vendor_configs) {
	vendor_config := vendor_configs[vendor]
	task_config := vendor_config[_]
	task.name == task_config.name
	count(task_config.inputs) == 0
}

does_task_match(task, vendor_configs) {
	vendor_config := vendor_configs[vendor]
	task_config := vendor_config[_]
	task.name == task_config.name
	count(task.inputs) == 0
}

does_task_match(task, vendor_configs) {
	vendor_config := vendor_configs[vendor]
	task_config := vendor_config[_]
	task.name == task_config.name
	not task_config.inputs
}

does_task_match(task, vendor_configs) {
	vendor_config := vendor_configs[vendor]
	task_config := vendor_config[_]
	task.name == task_config.name
	not task.inputs
}

# Task exists, and its inputs pass all input filters
does_task_match(task, vendor_configs) {
	vendor_config := vendor_configs[vendor]
	task_config := vendor_config[_]
	task.name == task_config.name
	every task_input in task.inputs {
		does_task_input_match(task_input, task_config.inputs)
	}
}

# Task input matches all filters for a string array
does_task_input_match(task_input, task_config_inputs) {
	task_config_inputs[task_input.name]
	regex.match(task_config_inputs[task_input.name][i], task_input.value[j])
}

# Task input matches all filters for a single string
does_task_input_match(task_input, task_config_inputs) {
	task_config_inputs[task_input.name]
	regex.match(task_config_inputs[task_input.name][i], task_input.value)
}

# Filtered input doesn't exist in task
does_task_input_match(task_input, task_config_inputs) {
	not task_config_inputs[task_input.name]
}
