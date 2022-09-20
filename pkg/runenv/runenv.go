package runenv

import (
	"os"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func DetectTriggeredBy(input string) string {
	if strings.ToLower(input) == "offline" {
		return "OFFLINE"
	}

	isCi := checkEnvValuesExistence(ciEnvs)
	isPr := isCi && checkEnvValuesExistence(prEnvs)

	triggeredBy := buildsecurity.TriggeredByEnum_TRIGGERED_BY_UNKNOWN

	if isPr {
		triggeredBy = buildsecurity.TriggeredByEnum_TRIGGERED_BY_PR
	} else if isCi {
		triggeredBy = buildsecurity.TriggeredByEnum_TRIGGERED_BY_PUSH
	}

	stringTriggerBy := mapTriggeredByToString(triggeredBy)
	log.Logger.Infof("Auto detected TRIGGERED_BY: %s", stringTriggerBy)
	return stringTriggerBy
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

func checkEnvValuesExistence(envs []string) bool {
	for _, env := range envs {
		if val, ok := os.LookupEnv(env); ok {
			return val != ""
		}
	}

	return false
}
