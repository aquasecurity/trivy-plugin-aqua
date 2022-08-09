package builtin.pipeline.ACTION_PINNED_VERSION

import data.lib.pipeline

__rego_metadata__ := {
	"id": "ACTION_PINNED_VERSION",
	"avd_id": "",
	"title": "Unrestricted action version",
	"severity": "MEDIUM",
	"type": "Pipeline Yaml Security Check",
	"description": "Pinning an action to a full length commit SHA is currently the only way to use an action as an immutable release. Pinning to a particular SHA helps mitigate the risk of a bad actor adding a backdoor to the action's repository, as they would need to generate a SHA-1 collision for a valid Git object payload.  Although pinning to a commit SHA is the most secure option, specifying a tag is more convenient and is widely used. If you'd like to specify a tag, then be sure that you trust the action's creators. The 'Verified creator' badge on GitHub Marketplace is a useful signal, as it indicates that the action was written by a team whose identity has been verified by GitHub. Note that there is risk to this approach even if you trust the author, because a tag can be moved or deleted if a bad actor gains access to the repository storing the action",
	"recommended_actions": "",
	"url": "",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "pipeline"}],
}

# Pin actions to a full length commit SHA
deny[msg] {
	input.jobs[i].steps[j].type == "task"
	input.jobs[i].steps[j].task.version_type != "commit"
	msg := {
		"msg": sprintf("Action %s version %s should be pinned to the commit sha", [input.jobs[i].steps[j].task.name, input.jobs[i].steps[j].task.version]),
		"startline": input.jobs[i].steps[j].file_reference.start_ref.line,
		"endline": input.jobs[i].steps[j].file_reference.end_ref.line,
	}
}
