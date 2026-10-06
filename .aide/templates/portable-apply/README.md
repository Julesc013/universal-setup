# AIDE Lite Apply Helpers

This portable package contains managed_sections.py, a standard-library parser
and fixture-safe patch planner for explicit generated-section markers. It
preserves manual text and refuses missing, duplicate, nested, malformed,
binary or ambiguous marker cases.

The shipped Python modules are __init__.py and managed_sections.py. Full-source
transaction execution and lifecycle runners are not included. This portable
fixture/planning surface does not authorize target mutations or live workers.
