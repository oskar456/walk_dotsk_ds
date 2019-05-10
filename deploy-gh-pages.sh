#!/bin/bash

git clone --branch=gh-pages https://${GITHUB_TOKEN}@github.com/${TRAVIS_REPO_SLUG}.git gh-pages 2>&1 > /dev/null
pushd gh-pages
export OUTDIR="$(date +%Y-%m-%d)"
mkdir -p "$OUTDIR"
mv ../domains-secured.txt ../domains-secured.csv ../domains-stats.csv "$OUTDIR"/
git rm -f current
ln -s "$OUTDIR" current
# Commit and push latest version
git add "$OUTDIR"
git config user.name  "Travis"
git config user.email "deploy@travis-ci.org"
git commit -m "Updated $OUTDIR stats"
git push -q origin gh-pages 2>&1 > /dev/null
popd
