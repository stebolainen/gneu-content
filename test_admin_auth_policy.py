#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PLAYBOOK = (ROOT / "docs" / "ADMIN_PLAYBOOK.md").read_text(encoding="utf-8")
SECTION = PLAYBOOK.split("### Profilsäker Adam-auth-status\n", 1)[1].split("\n## ", 1)[0]

EXPECTED_COMMAND = """HERMES_HOME=/root/.hermes/profiles/gneu \\
/usr/bin/python3 -I \\
/root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py status"""

assert EXPECTED_COMMAND in SECTION, "Admin auth policy lost the exact GNEU-profile status command"
assert "OGILTIG\nEVIDENS" in SECTION, "Admin auth policy lost invalid-evidence handling"
assert "automatisk fail-closed-paus" in SECTION, "Admin auth policy lost the fail-closed pause guard"
assert "gneu-content-watch" in SECTION, "Admin auth policy no longer protects the Adam watch job"

print("GNEU Admin Adam-auth policy contract OK")
