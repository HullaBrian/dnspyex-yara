"""Compile every generated .yar listed in manifest.json and check each expected rule matches its target file."""
import json
import os
import sys

import yara

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
failed = 0
for entry in manifest:
    name = os.path.basename(entry["rules"])
    try:
        rules = yara.compile(filepath=entry["rules"])
    except yara.SyntaxError as e:
        print(f"SYNTAX ERROR {name}: {e}")
        failed += 1
        continue
    warnings = getattr(rules, "warnings", [])
    matched = {m.rule for m in rules.match(entry["target"], timeout=600)}
    missing = [r for r in entry["expected"] if r not in matched]
    status = "FAIL" if missing else "OK  "
    total = len(entry["expected"])
    print(f"{status} {name:36} {total - len(missing)}/{total} rules matched, {len(warnings)} compiler warnings")
    if missing:
        failed += 1
        print("     missing:", missing[:20])
sys.exit(1 if failed else 0)
