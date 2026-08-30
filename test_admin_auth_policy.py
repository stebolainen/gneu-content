#!/usr/bin/env python3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PLAYBOOK = (ROOT / "docs" / "ADMIN_PLAYBOOK.md").read_text(encoding="utf-8")
SECTION = PLAYBOOK.split("### Profilsäker Adam-auth-status\n", 1)[1].split("\n## ", 1)[0]
RUNTIME_README = (ROOT / "runtime" / "adam" / "README.md").read_text(encoding="utf-8")
PROMPT_PATH = ROOT / "runtime" / "adam" / "gneu-content-watch.prompt.md"

EXPECTED_COMMAND = """HERMES_HOME=/root/.hermes/profiles/gneu \\
/usr/bin/python3 -I \\
/root/.hermes/profiles/gneu/scripts/gneu-content-adam-auth.py status"""
PROMPT_SETUP = (
    "PROMPT_SENTINEL='__GNEU_PROMPT_SENTINEL__'\n"
    "PROMPT=\"$(cat runtime/adam/gneu-content-watch.prompt.md; printf '%s' \"$PROMPT_SENTINEL\")\"\n"
    'PROMPT="${PROMPT%$PROMPT_SENTINEL}"'
)
DOCUMENTED_PROMPT_SETUP = "\n".join(f"   {line}" for line in PROMPT_SETUP.splitlines())
BROKEN_PROMPT_INSTALL = '--prompt "$(cat runtime/adam/gneu-content-watch.prompt.md)"'

assert EXPECTED_COMMAND in SECTION, "Admin auth policy lost the exact GNEU-profile status command"
assert "OGILTIG\nEVIDENS" in SECTION, "Admin auth policy lost invalid-evidence handling"
assert "automatisk fail-closed-paus" in SECTION, "Admin auth policy lost the fail-closed pause guard"
assert "gneu-content-watch" in SECTION, "Admin auth policy no longer protects the Adam watch job"
assert EXPECTED_COMMAND in RUNTIME_README, "runtime auth status lost the explicit GNEU profile"
assert BROKEN_PROMPT_INSTALL not in RUNTIME_README, "runtime prompt install strips terminal newlines"
assert DOCUMENTED_PROMPT_SETUP in RUNTIME_README, "runtime prompt install lost the newline-safe sentinel setup"
assert '--prompt "$PROMPT"' in RUNTIME_README, "runtime prompt is not passed as one quoted argument"

original_prompt = PROMPT_PATH.read_bytes()
assert original_prompt.endswith(b"\n"), "runtime prompt must exercise terminal-LF preservation"
reconstructed_prompt = subprocess.run(
    ["/bin/bash", "-c", PROMPT_SETUP + "\nprintf '%s' \"$PROMPT\""],
    cwd=ROOT,
    check=True,
    capture_output=True,
).stdout
assert reconstructed_prompt == original_prompt, "sentinel method changed the exact runtime prompt bytes"

print("GNEU Admin Adam-auth policy contract OK")
