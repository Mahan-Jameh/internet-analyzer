"""
Diagnostic engine: structured results, normalized errors, retry policy,
dependency graph, correlation (root-cause) engine and layered reports.

Layering (see docs/REFACTOR_NOTES.md):

    A. raw observation      - the socket / HTTP call and its exception
    B. normalized result    - :class:`results.TestResult` (what was measured)
    C. interpretation       - ``TestResult.interpretation`` / ``confidence``
    D. root-cause analysis  - :mod:`correlation` over all results together
"""
