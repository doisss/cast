"""Shared fixtures: realistic scanner payloads captured from real tool output.

These are the shapes that matter. The engine adapters are the most fragile code
in the project (they parse somebody else's JSON) and previously had zero tests,
which is how grype's list-shaped `cvss` shipped as always-0.0.
"""