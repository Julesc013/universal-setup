# AIDE Lite Pack Import Report

## Target

- repo_id: <target_repo_id>
- repo_name: <target_repo_name>
- current_phase: <target_current_phase>

## Import Result

- pack: aide-lite-pack-v0
- dry_run: <dry_run_result>
- import: <import_result>
- conflicts: <conflicts>

## Required Target Initialization

- Run `py -3 .aide/scripts/aide_lite.py doctor`
- Run `py -3 .aide/scripts/aide_lite.py snapshot`
- Run `py -3 .aide/scripts/aide_lite.py index`
- Run `py -3 .aide/scripts/aide_lite.py pack --task "<target_next_task>"`

## Boundary Notes

No source queue history, source memory, generated context, reports, local
state, secrets, raw prompts, or raw responses should be present in the target.
