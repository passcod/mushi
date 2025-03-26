#!/usr/bin/env bash

set -euo pipefail

ver="${1:-}"
if [[ -z "$ver" ]]; then
  echo "Usage: $0 <version>"
  exit 1
elif [[ "$ver" == "patch" || "$ver" == "minor" || "$ver" == "major" ]]; then
  echo "Error: version must be an exact number, not a word"
  exit 2
fi

if git branch --show-current | grep -v '^main$' >/dev/null; then
  echo "Error: must be on main"
  exit 3
fi

if git status --porcelain=v2 | grep . >/dev/null; then
  echo "Error: repo must be clean"
  exit 4
fi

if [[ ! -d .git ]]; then
  echo "Error: must be at repo root"
  exit 5
fi

set -x

pushd lib
sed -E -i "s|^version = \".+\"$|version = \"$ver\"|1" Cargo.toml
cargo check
cargo publish --allow-dirty
popd

pushd nodejs
sed -E -i "s|^mushi = \".+\"$|version = \"$ver\"|1" Cargo.toml
cargo update
npm run build
npm version "$ver"
npm run prepublishOnly
popd

git commit -am "$ver"
git tag -sam {,}"v$ver"
git push
