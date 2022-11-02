SHELL=/usr/bin/env bash


.PHONY: test
test:
	if cat ./plugin.yaml | grep uri: | cut -c 10-200 | xargs -n 1 curl -o /dev/null --silent --head --write-out '%{http_code}\n'  -L | grep -q "404"; then echo 'Artifacts links are broken'; exit 1;else echo 'Artifacts links are valid';fi
