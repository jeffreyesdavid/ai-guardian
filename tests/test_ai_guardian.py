#!/usr/bin/env python3
"""Tests for ai-guardian. Builds a fake home folder with risky AI setups and
checks that each one is caught, that safe setups stay quiet, and that no
secret is ever printed in full.

Fake keys are assembled at runtime so no secret-looking string lives in the repo.
Run: python3 tests/test_ai_guardian.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ai_guardian as ag  # noqa: E402

FAKE_ANTHROPIC = "sk-" + "ant-" + "api03-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
FAKE_OPENAI = "sk-" + "proj-" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6"
FAKE_GITHUB = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def write(home, rel, content):
    path = os.path.join(home, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content if isinstance(content, str) else json.dumps(content, indent=2))
    return path


def scan(home):
    return ag.Scanner(home, check_live=False).run()


def titles(sc):
    return [f["title"] for f in sc.findings]


class RiskyHome(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        home = cls.home = cls.tmp.name
        write(home, "Library/Application Support/Claude/claude_desktop_config.json", {
            "mcpServers": {
                "filesystem": {"command": "npx",
                               "args": ["-y", "@modelcontextprotocol/server-filesystem", home]},
                "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.4.0"],
                           "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GITHUB}},
                "remote-notes": {"url": "http://notes.example.com/mcp"},
                "desktop-commander": {"command": "npx", "args": ["-y", "@wonderwhy-er/desktop-commander"]},
                "keys": {"command": "node", "args": ["server.js", os.path.join(home, ".ssh")]},
            }
        })
        write(home, ".claude/settings.json", {
            "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}
        })
        write(home, ".cursor/mcp.json", {
            "mcpServers": {"db": {"command": "uvx", "args": ["mcp-server-sqlite"],
                                  "env": {"DB_PASSWORD": "hunter2-super-secret-pw"}}}
        })
        write(home, ".gemini/settings.json", {"autoAccept": True})
        write(home, ".zshrc", f'export ANTHROPIC_API_KEY="{FAKE_ANTHROPIC}"\nexport OPENAI_API_KEY={FAKE_OPENAI}\n')
        ext = "Library/Application Support/Google/Chrome/Default/Extensions/abc/1.0/manifest.json"
        write(home, ext, {"name": "ChatGPT Sidebar Assistant", "permissions": ["storage"],
                          "host_permissions": ["<all_urls>"]})
        write(home, "Library/Application Support/Google/Chrome/Default/Extensions/def/1.0/manifest.json",
              {"name": "Dark Reader", "host_permissions": ["<all_urls>"]})
        cls.sc = scan(home)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def has(self, text, sev=None):
        for f in self.sc.findings:
            if text.lower() in f["title"].lower() and (sev is None or f["severity"] == sev):
                return True
        self.fail(f"expected finding containing {text!r} ({sev}); got:\n  " + "\n  ".join(titles(self.sc)))

    def test_discovers_mcp_servers(self):
        names = {a["name"] for a in self.sc.agents if a["type"] == "mcp"}
        self.assertTrue({"filesystem", "github", "remote-notes", "desktop-commander", "db"} <= names)

    def test_home_folder_access(self):
        self.has("can access your entire home folder", "HIGH")

    def test_sensitive_folder(self):
        self.has("can read a sensitive folder", "HIGH")

    def test_plaintext_token_in_config(self):
        self.has("GitHub token in plain text", "HIGH")

    def test_unencrypted_remote_server(self):
        self.has("without encryption", "HIGH")

    def test_unpinned_package(self):
        self.has("'filesystem' auto-installs", "MEDIUM")
        self.has("'db' auto-installs", "MEDIUM")

    def test_pinned_package_not_flagged(self):
        self.assertFalse(any("'github' auto-installs" in t for t in titles(self.sc)))

    def test_shell_capable_server(self):
        self.has("'desktop-commander' can run commands", "MEDIUM")

    def test_password_in_env(self):
        self.has("stores DB_PASSWORD in plain text", "MEDIUM")

    def test_bypass_permissions(self):
        self.has("skip all permission prompts", "HIGH")
        self.has("may run any shell command", "HIGH")

    def test_yolo_flag(self):
        self.has("auto-approves actions", "HIGH")

    def test_shell_profile_keys(self):
        self.has("Anthropic API key in your shell profile", "MEDIUM")
        self.has("OpenAI API key in your shell profile", "MEDIUM")
        # the Anthropic key must not be double-counted as an OpenAI key
        self.assertEqual(sum("shell profile" in t for t in titles(self.sc)), 2)

    def test_ai_extension_flagged_but_not_others(self):
        self.has("AI extension can read every website: ChatGPT Sidebar Assistant", "MEDIUM")
        self.assertFalse(any("Dark Reader" in t for t in titles(self.sc)))

    def test_high_before_medium(self):
        sev = [f["severity"] for f in self.sc.findings]
        self.assertEqual(sev, sorted(sev, key=lambda s: ag.SEVERITY_ORDER[s]))

    def test_secrets_never_printed_in_full(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ag.print_report(self.sc, False)
            print(json.dumps(ag.to_json(self.sc)))
        out = buf.getvalue()
        for secret in (FAKE_ANTHROPIC, FAKE_OPENAI, FAKE_GITHUB, "hunter2-super-secret-pw"):
            self.assertNotIn(secret, out)

    def test_exit_code_on_high(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ag.main(["--home", self.home, "--no-live", "--json"]), 1)
            self.assertEqual(ag.main(["--home", self.home, "--no-live", "--json", "--fail-on", "none"]), 0)


class SafeHome(unittest.TestCase):
    def test_safe_setup_is_quiet(self):
        with tempfile.TemporaryDirectory() as home:
            write(home, ".cursor/mcp.json", {"mcpServers": {
                "docs": {"command": "npx", "args": ["-y", "@acme/docs-server@2.1.0",
                                                    os.path.join(home, "projects", "site")],
                         "env": {"API_KEY": "${DOCS_API_KEY}"}},
                "remote": {"url": "https://mcp.example.com"},
            }})
            write(home, ".claude/settings.json", {"permissions": {"allow": ["Bash(npm test)"]}})
            write(home, ".zshrc", 'export PATH="$HOME/bin:$PATH"\n')
            sc = scan(home)
            self.assertEqual(sc.findings, [], titles(sc))
            self.assertEqual({a["name"] for a in sc.agents if a["type"] == "mcp"}, {"docs", "remote"})

    def test_empty_home(self):
        with tempfile.TemporaryDirectory() as home:
            sc = scan(home)
            self.assertEqual(sc.findings, [])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ag.main(["--home", home, "--no-live"]), 0)

    def test_broken_json_does_not_crash(self):
        with tempfile.TemporaryDirectory() as home:
            write(home, ".cursor/mcp.json", "{ this is not json")
            scan(home)


class Helpers(unittest.TestCase):
    def test_mask(self):
        m = ag.mask(FAKE_OPENAI)
        self.assertNotIn(FAKE_OPENAI[8:-2], m)
        self.assertTrue(m.startswith("sk-pro"))
        self.assertEqual(ag.mask("short"), "****")

    def test_process_label(self):
        self.assertEqual(ag.process_label(
            "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"), "Claude")
        self.assertEqual(ag.process_label("/usr/local/bin/ollama"), "ollama")
        self.assertIsNone(ag.process_label(
            "/System/Library/PrivateFrameworks/ViewBridge.framework/CursorUIViewService"))
        self.assertIsNone(ag.process_label("/usr/bin/vim"))

    def test_only_newest_extension_version(self):
        with tempfile.TemporaryDirectory() as home:
            base = "Library/Application Support/Google/Chrome/Default/Extensions/xyz/"
            for v in ("1.0.9_0", "1.0.10_0"):
                write(home, base + v + "/manifest.json",
                      {"name": "Claude", "host_permissions": ["<all_urls>"]})
            sc = scan(home)
            exts = [a for a in sc.agents if a["type"] == "extension"]
            self.assertEqual(len(exts), 1)
            self.assertIn("1.0.10_0", exts[0]["where"])

    def test_ai_name(self):
        self.assertTrue(ag.is_ai_name("Claude for Chrome"))
        self.assertTrue(ag.is_ai_name("AI Grammar Checker"))
        self.assertFalse(ag.is_ai_name("Dark Reader"))
        self.assertFalse(ag.is_ai_name("Adblock Plus"))  # 'ai' must be a whole word


if __name__ == "__main__":
    unittest.main(verbosity=2)
