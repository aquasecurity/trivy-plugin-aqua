#!/usr/bin/env bash

set -ex

function log() {
  message=$1

  echo `date +"%T"` $message
}

log "Switching to master branch"
git checkout master

log "Getting latest tags"
git fetch --tags
LATEST_TAG=`git describe --tag`

sed  -e "s/PLACEHOLDERVERSION/${GITHUB_REF##*/}/g" .github/plugin_template.yaml > plugin.yaml

git checkout -b "plugin-update-${LATEST_TAG}"

git add plugin.yaml
git commit -m "Updateing plugin to latest tag ${LATEST_TAG}" || true
git push --set-upstream origin "plugin-update-${LATEST_TAG}" || true

