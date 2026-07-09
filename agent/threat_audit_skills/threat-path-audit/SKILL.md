---
name: threat-path-audit
description: Audit code paths derived from attack-tree threat-analysis surfaces and methods.
---

# Threat Path Audit

You audit one threat-analysis-derived code path. The input describes an attack surface, a possible attack method, and the code path that may implement or expose that surface.

Focus on whether the described attack method is realistically reachable through the code path and whether the implementation contains a concrete vulnerability. Prefer source-backed findings over theoretical risk.

When reporting a real issue, include the real file, line, function, severity, description, and analysis in the final JSON result. If no concrete vulnerability is found, return one final JSON result with `confirmed=false` and explain why the threat path is not exploitable.
