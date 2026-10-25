#!/bin/sh
# Mirror artifact/iotsecfix-1.0.0/ into repo/ (a git checkout of the private GitHub repo) and
# commit as Anonymous. Usage: sh code/sync_repo.sh "<commit message>"   (push separately)
set -eu
cd "$(dirname "$0")/.."
rsync -a --delete --exclude .git --exclude __pycache__ artifact/iotsecfix-1.0.0/ repo/
printf '__pycache__/\ndata/raw/\npaper/\n.env\n' > repo/.gitignore
git -C repo add -A
git -C repo -c user.name=Anonymous -c user.email=anonymous@example.com commit -q -m "$1" || echo "nothing to commit"
git -C repo log --oneline -1
