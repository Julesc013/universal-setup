# AIDE Changelog Drafts

`.aide/changelog/` stores preview-only changelog and release-note artifacts generated from local Git history.

Use:

```text
py -3 .aide/scripts/aide_lite.py changelog preview
py -3 .aide/scripts/aide_lite.py changelog validate
py -3 .aide/scripts/aide_lite.py changelog status
```

Generated previews are review inputs. They do not create tags, GitHub Releases, branch changes, or published release history.
