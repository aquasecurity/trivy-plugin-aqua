#!/usr/bin/env bash

echo "update plugin.yaml"

sed  -e "s/PLACEHOLDERVERSION/${GITHUB_REF##*/}/g" .github/plugin_template.yaml > plugin.yaml

git fetch --all
git checkout master
git pull
git config --global user.name "GitHub Actions Build"
git config --global user.email github-action@aquasec.com
git add plugin.yaml
git commit -m "GitHub Actions Build: Update plugin version" || true
git push --set-upstream origin HEAD:master || true

