package runenv

import (
	"os"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func DetectTriggeredBy() string {
	isCi := checkEnvValueExistence(ciEnvs...)
	isPr := checkEnvValueExistence(prEnvs...)

	if !isCi {
		return mapTriggeredByToString(buildsecurity.TriggeredByEnum_TRIGGERED_BY_UNKNOWN)
	} else if isPr {
		return mapTriggeredByToString(buildsecurity.TriggeredByEnum_TRIGGERED_BY_PR)
	}

	return mapTriggeredByToString(buildsecurity.TriggeredByEnum_TRIGGERED_BY_PUSH)
}

func mapTriggeredByToString(triggerBy buildsecurity.TriggeredByEnum) string {
	switch triggerBy {
	case buildsecurity.TriggeredByEnum_TRIGGERED_BY_PR:
		return "PR"
	case buildsecurity.TriggeredByEnum_TRIGGERED_BY_PUSH:
		return "PUSH"
	default:
		return "UNKNOWN"
	}

}

func checkEnvValueExistence(envs ...string) bool {
	for _, env := range envs {
		if val, ok := os.LookupEnv(env); ok {
			return val != ""
		}
	}

	return false
}
