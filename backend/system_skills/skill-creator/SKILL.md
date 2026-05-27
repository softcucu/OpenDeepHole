---
name: skill-creator
description: Create concise OpenDeepHole project-level audit skills from a user-provided name, description, and task input.
---

# Skill Creator

Create a single OpenDeepHole project-level audit skill from the supplied name, description, and user input.

## Output Contract

Return only one JSON object. Do not wrap it in prose. The object must contain:

- `skill_md`: complete `SKILL.md` content, including YAML frontmatter.
- `scenarios_md`: user-facing applicability notes for the SKILL market. Use an empty string only when no useful scenarios can be stated.
- `summary`: one short sentence describing the generated skill.

## Generated SKILL Rules

- Generate a pure SKILL project-level checker only.
- Do not generate `analyzer.py`, Semgrep rules, scripts, resources, README files, changelogs, install guides, or auxiliary documentation.
- The frontmatter must include `name` and `description`.
- The body must be concise and operational. Tailor it to the supplied task instead of giving generic security guidance.
- The SKILL must instruct the auditor to inspect the target code actively, identify concrete file/function/line evidence, and call `submit_result`.
- If multiple real issues are found, each issue must be submitted with a separate `submit_result` call.
- If no real issue is found, the auditor must still call `submit_result` once with `confirmed=false`.

## Required Audit Guidance

The generated SKILL should define:

- Target behavior or vulnerability pattern to look for.
- Evidence needed to confirm a real issue.
- Common false-positive conditions that should be rejected.
- How to reason about triggerability, impact, and missing protections.
- Exact result submission expectations for `confirmed`, `severity`, `description`, `ai_analysis`, `file`, `line`, and `function`.
