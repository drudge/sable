#!/bin/sh
# Cloud sessions start with the container's git identity (Claude, signed with
# a Claude key). Commit as the maintainer instead, unsigned like local commits.
[ "$CLAUDE_CODE_REMOTE" = "true" ] || exit 0
cd "$(dirname "$0")/../.." || exit 0
git config user.name "Nicholas Penree"
git config user.email "nick@penree.com"
git config commit.gpgsign false
