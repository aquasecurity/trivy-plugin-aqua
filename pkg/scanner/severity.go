package scanner

type Severities []string

var AllSeverities = Severities{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severities) Any(checkSev string) bool {

	for _, severity := range s {
		if checkSev == severity {
			return true
		}
	}
	return false
}
