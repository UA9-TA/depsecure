# DepSecure — Status

**Last updated:** 2026-05-15

## State: ⏳ Assigned to Jules

## What exists
- JULES_PROMPT.md: Full build spec committed to main
- README spec includes ecosystem cross-links table (all 9 tools)

## Jules task
Block vulnerable dependencies at commit time using OSV vulnerability database.
Jules will build: cli.py, parsers/ (requirements/pyproject/pipfile/npm), osv_client.py, cache.py, checker.py

## Pending
- [ ] Jules PR — watch for it, expect same fixes as RootCause (model name, pycache, CI)
- [ ] Review + merge Jules PR
- [ ] HN launch (Day 3 of staggered launch queue)

## Repo
- GitHub: https://github.com/UA9-TA/depsecure
- Branch: main
- License: MIT
