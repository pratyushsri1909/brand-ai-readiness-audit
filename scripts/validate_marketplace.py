import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def validate():
    errors = []
    manifest_path = os.path.join(ROOT, "marketplace.json")
    if not os.path.isfile(manifest_path):
        return ["Missing marketplace.json"]
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot read valid marketplace.json: {exc}"]

    if manifest.get("name") != "brand-ai-readiness-audit":
        errors.append("Unexpected marketplace name")
    if not isinstance(manifest.get("skills"), list) or not manifest["skills"]:
        errors.append("skills must be a non-empty array")
        return errors

    entrypoints = [s for s in manifest["skills"] if s.get("entrypoint") is True]
    if len(entrypoints) != 1:
        errors.append(f"Expected exactly 1 entrypoint, found {len(entrypoints)}")

    seen_ids = set()
    seen_paths = set()
    for skill in manifest["skills"]:
        sid = skill.get("id")
        path_rel = skill.get("path")
        if not sid or not path_rel:
            errors.append("Every skill needs id and path")
            continue
        if sid in seen_ids:
            errors.append(f"Duplicate skill id: {sid}")
        seen_ids.add(sid)
        if path_rel in seen_paths:
            errors.append(f"Duplicate skill path: {path_rel}")
        seen_paths.add(path_rel)
        path = os.path.abspath(os.path.join(ROOT, path_rel))
        if not path.startswith(ROOT + os.sep) or not os.path.isdir(path):
            errors.append(f"Skill path missing or outside root: {path_rel}")
            continue
        skill_md = os.path.join(path, "SKILL.md")
        if not os.path.isfile(skill_md):
            errors.append(f"Missing SKILL.md in {path_rel}")
            continue
        text = open(skill_md, encoding="utf-8").read()
        if not re.search(r"\A---\s*\nname:\s*[^\n]+\ndescription:\s*[^\n]+\nlicense:\s*[^\n]+\n---\s*\n", text):
            errors.append(f"Invalid SKILL.md frontmatter: {path_rel}")
        for heading in ("## When to use", "## Inputs", "## Procedure", "## Output"):
            if heading not in text:
                errors.append(f"Missing '{heading}' in {path_rel}/SKILL.md")
        if sid == "audit-orchestrator" and not os.path.isfile(os.path.join(path, "scripts", "run_audit.py")):
            errors.append("Entrypoint run_audit.py is missing")
        if sid != "audit-orchestrator" and not os.path.isfile(os.path.join(path, "scripts", "detector.py")):
            errors.append(f"Detector script missing in {path_rel}")

    for root, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {"__pycache__", ".pytest_cache"}]
        for name in files:
            if name.endswith(('.pyc', '.pyo')):
                errors.append(f"Forbidden compiled file: {os.path.join(root, name)}")
    return errors


if __name__ == "__main__":
    errors = validate()
    if errors:
        print("MARKETPLACE VALIDATION FAILED")
        print("\n".join(errors))
        sys.exit(1)
    print("MARKETPLACE VALIDATION PASSED")
