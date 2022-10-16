package oss

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	"github.com/samber/lo"
)

type PackageJson struct {
	Dependencies Dependencies `json:"dependencies,omitempty"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Name    string
	Version string
	Line    int32
	Path    string
}

func (pj *PackageJson) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	lineSep := []byte{'\n'}

	// Unmarshal dependencies
	if deps, ok := m["dependencies"]; ok {
		if deps, ok := deps.(map[string]interface{}); ok {
			pj.Dependencies = make(Dependencies)
			for name, ver := range deps {
				if ver, ok := ver.(string); ok {
					nameIndex := bytes.Index(data, []byte(fmt.Sprintf(`"%s":`, name)))
					line := int32(bytes.Count(data[:nameIndex], lineSep))
					pj.Dependencies[name] = Dependency{
						Name:    name,
						Version: ver,
						Line:    lo.Ternary(line == 0, int32(commenter.FIRST_AVAILABLE_LINE), line+1),
					}
				}
			}
		}
	}

	return nil
}

func (ds Dependencies) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(ds))
	for k, v := range ds {
		m[k] = v.Version
	}
	return json.Marshal(m)
}
