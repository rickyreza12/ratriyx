#!/bin/bash
cd /mnt/e/Projects/NyxRoute/apps || exit 9
echo "nyxroute occurrences outside target (case-insensitive):"
grep -rniI "nyxroute" --exclude-dir=target --exclude-dir=.git . | cut -c1-140
echo "git state: commits=$(git rev-list --all --count 2>/dev/null || echo 0) remotes=$(git remote | wc -l) tracked=$(git ls-files | wc -l)"
ls -d .git >/dev/null && echo ".git is inside apps/ only"
ls -d /mnt/e/Projects/NyxRoute/.git 2>&1 | head -1
