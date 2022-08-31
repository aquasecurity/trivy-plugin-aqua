#!/usr/bin/env bash

set -e


git checkout master
git fetch --tags --all
git pull

LATEST_TAG=`git describe --tags --abbrev=0`
read -p "The last tag was: ${LATEST_TAG}, what tag should I create? " TAG;

if [[ -z $TAG ]]; then
  echo "you need to specify a new tag"
  exit 1
fi

git tag -a ${TAG} -m ${TAG}
git push --tag