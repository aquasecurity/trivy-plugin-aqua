package oss

import "encoding/json"

type PackageJson struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Dependencies Dependencies `json:"dependencies,omitempty"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Name    string
	Version string
	Line    int
}

func (ds *Dependencies) UnmarshalJSON(data []byte) error {
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ds = make(Dependencies, len(m))
	for k, v := range m {
		(*ds)[k] = Dependency{
			Name:    k,
			Version: v,
			Line:    -1,
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
