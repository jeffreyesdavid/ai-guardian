#!/usr/bin/env python3
"""
ai-guardian v1.1.0
Find the AI agents on your machine and see what they can touch.

Discover: AI apps, command-line agents, running AI processes, AI browser
          extensions, and MCP servers (the plugins that give agents access
          to your files, apps, and accounts).
Map:      flags risky setups, like API keys in plain text, agents with access
          to your whole drive, agents allowed to run any command without
          asking, and local AI servers exposed to your whole Wi-Fi network.

Defensive and read-only: it reads config files and process lists. It never
changes anything, never sends data anywhere, and masks every secret it finds.

MIT License - github.com/jeffreyesdavid/ai-guardian
"""

import argparse
import glob
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone

VERSION = "1.1.0"

# ---------------------------------------------------------------- catalog

AI_APPS = {
    "Claude": "Anthropic Claude desktop",
    "ChatGPT": "OpenAI ChatGPT desktop",
    "Cursor": "Cursor AI code editor",
    "Windsurf": "Windsurf AI code editor",
    "Ollama": "Ollama local AI models",
    "LM Studio": "LM Studio local AI models",
    "Perplexity": "Perplexity AI",
    "Copilot": "Microsoft Copilot",
    "Gemini": "Google Gemini",
    "Jan": "Jan local AI",
    "GPT4All": "GPT4All local AI",
    "Msty": "Msty local AI",
    "Zed": "Zed editor (AI features)",
    "Warp": "Warp AI terminal",
    "Comet": "Perplexity Comet AI browser",
    "Dia": "Dia AI browser",
}

AI_CLIS = {
    "claude": "Claude Code agent",
    "codex": "OpenAI Codex agent",
    "gemini": "Gemini CLI agent",
    "ollama": "Ollama local models",
    "aider": "Aider coding agent",
    "goose": "Goose agent",
    "opencode": "opencode agent",
    "cursor-agent": "Cursor agent",
    "copilot": "GitHub Copilot CLI",
    "lms": "LM Studio CLI",
    "llm": "llm CLI",
    "openclaw": "OpenClaw agent",
}

AI_PROCESS_WORDS = [
    "ollama", "claude", "chatgpt", "cursor", "windsurf", "lm studio", "lmstudio",
    "codex", "aider", "goose", "opencode", "copilot", "gemini", "mcp-server",
    "modelcontextprotocol", "openclaw", "llama-server", "llama.cpp",
]

AI_EXTENSION_WORDS = [
    "ai", "gpt", "chatgpt", "claude", "gemini", "copilot", "llm", "assistant",
    "perplexity", "grammarly", "writer", "summar", "agent", "monica", "merlin",
    "sider", "harpa", "maxai",
]

# Config files where AI agents keep MCP servers and permissions (macOS + Linux)
MCP_CONFIGS = [
    ("Claude desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
    ("Claude desktop", ".config/Claude/claude_desktop_config.json"),
    ("Claude Code", ".claude.json"),
    ("Claude Code", ".claude/settings.json"),
    ("Claude Code", ".claude/settings.local.json"),
    ("Claude Code", ".mcp.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("Windsurf", ".codeium/windsurf/mcp_config.json"),
    ("VS Code", "Library/Application Support/Code/User/mcp.json"),
    ("VS Code", ".config/Code/User/mcp.json"),
    ("VS Code", "Library/Application Support/Code/User/settings.json"),
    ("VS Code", ".config/Code/User/settings.json"),
    ("Gemini CLI", ".gemini/settings.json"),
    ("Codex", ".codex/config.json"),
    ("Goose", ".config/goose/config.yaml"),
    ("LM Studio", ".lmstudio/mcp.json"),
]

SHELL_PROFILES = [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile",
                  ".config/fish/config.fish", ".env"]

BROWSER_EXT_DIRS = [
    ("Chrome", "Library/Application Support/Google/Chrome"),
    ("Chrome", ".config/google-chrome"),
    ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
    ("Brave", ".config/BraveSoftware/Brave-Browser"),
    ("Edge", "Library/Application Support/Microsoft Edge"),
    ("Edge", ".config/microsoft-edge"),
    ("Arc", "Library/Application Support/Arc/User Data"),
]

# Patterns for secrets that should never sit in plain text
SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub token", re.compile(r"github_pat_[A-Za-z0-9_]{30,}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Stripe key", re.compile(r"[sr]k_live_[A-Za-z0-9]{20,}")),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z0-9]{30,}")),
]
SECRET_NAME = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE[_-]?KEY)", re.I)

SENSITIVE_PATHS = [".ssh", ".aws", ".gnupg", "Library/Keychains", ".config/gcloud",
                   "Library/Application Support/Google/Chrome", ".kube", ".docker"]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
LIVE_TYPES = ("process", "server")  # depend on timing, not on what's installed


# ---------------------------------------------------------------- helpers

def mask(secret):
    """Never print a full secret. Keep enough to recognize it."""
    s = str(secret)
    if len(s) <= 8:
        return "****"
    return s[:6] + "…" + "*" * 4 + s[-2:]


def read_text(path, limit=2_000_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except (OSError, UnicodeError):
        return None


def load_json(path):
    text = read_text(path)
    if text is None:
        return None
    # tolerate // comments that some editors allow in settings files
    cleaned = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None


def world_readable(path):
    try:
        return bool(os.stat(path).st_mode & stat.S_IROTH)
    except OSError:
        return False


def process_label(comm):
    """Turn a process path into a friendly AI app name, or None if it isn't AI.
    Helpers inside an app bundle are grouped under the app (Claude.app/... -> Claude)."""
    low = comm.lower()
    if low.startswith(("/system/", "/usr/libexec/", "/usr/sbin/")):
        return None  # macOS's own services (e.g. CursorUIViewService is not Cursor)
    if "ai-guardian" in low or "ai_guardian" in low:
        return None
    if not any(w in low for w in AI_PROCESS_WORDS):
        return None
    m = re.search(r"/([^/]+)\.app/", comm + "/")
    return m.group(1) if m else os.path.basename(comm).split(" ")[0]


def is_ai_name(name):
    """Short words (like 'ai') must match a whole word; longer ones can start a word."""
    words = re.findall(r"[a-z0-9]+", name.lower())
    for k in AI_EXTENSION_WORDS:
        for w in words:
            if w == k or (len(k) >= 4 and w.startswith(k)):
                return True
    return False


def find_secrets(text):
    hits = []
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            hits.append((label, m.group(0)))
    # de-dupe (Anthropic keys also match the OpenAI pattern)
    seen, out = set(), []
    for label, val in sorted(hits, key=lambda h: 0 if "Anthropic" in h[0] else 1):
        if val in seen or any(val in s or s in val for s in seen):
            continue
        seen.add(val)
        out.append((label, val))
    return out


# ---------------------------------------------------------------- scanner

class Scanner:
    def __init__(self, home, check_live=True):
        self.home = os.path.abspath(os.path.expanduser(home))
        self.check_live = check_live
        self.agents = []    # discovered things
        self.findings = []  # risks

    def h(self, rel):
        return os.path.join(self.home, rel)

    def short(self, path):
        return path.replace(self.home, "~", 1) if path.startswith(self.home) else path

    def agent(self, kind, name, where, detail=""):
        self.agents.append({"type": kind, "name": name, "where": self.short(where), "detail": detail})

    @property
    def installed(self):
        return [a for a in self.agents if a["type"] not in LIVE_TYPES]

    @property
    def running(self):
        return [a for a in self.agents if a["type"] in LIVE_TYPES]

    def finding(self, sev, title, where, why, fix):
        self.findings.append({"severity": sev, "title": title, "where": self.short(where),
                              "why": why, "fix": fix})

    # ---- discover

    def scan_apps(self):
        roots = ["/Applications", self.h("Applications")]
        for root in roots:
            if not os.path.isdir(root):
                continue
            for entry in sorted(os.listdir(root)):
                if not entry.endswith(".app"):
                    continue
                base = entry[:-4]
                for key, desc in AI_APPS.items():
                    if base == key or base.startswith(key + " "):
                        self.agent("app", base, os.path.join(root, entry), desc)
                        break

    def scan_clis(self):
        extra = [self.h(".local/bin"), self.h(".npm-global/bin"), self.h(".bun/bin"),
                 self.h(".cargo/bin"), "/opt/homebrew/bin", "/usr/local/bin"]
        path_dirs = os.environ.get("PATH", "").split(os.pathsep) + extra
        seen = set()
        for name, desc in AI_CLIS.items():
            for d in path_dirs:
                p = os.path.join(d, name)
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    real = os.path.realpath(p)
                    if real not in seen:
                        seen.add(real)
                        self.agent("cli", name, p, desc)
                    break

    def scan_processes(self):
        if not self.check_live:
            return
        try:
            out = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True,
                                 text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return
        groups = {}
        for line in out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            pid, comm = parts
            label = process_label(comm)
            if label is None:
                continue
            groups.setdefault(label, []).append(pid)
        for label, pids in sorted(groups.items()):
            detail = "running now" if len(pids) == 1 else f"running now ({len(pids)} processes)"
            self.agent("process", label, f"pid {pids[0]}", detail)

    def scan_extensions(self):
        for browser, rel in BROWSER_EXT_DIRS:
            base = self.h(rel)
            if not os.path.isdir(base):
                continue
            # Chrome keeps old version folders around; only check the newest per extension
            newest = {}
            for manifest in glob.glob(os.path.join(base, "*", "Extensions", "*", "*", "manifest.json")):
                ext_root = os.path.dirname(os.path.dirname(manifest))
                ver = os.path.basename(os.path.dirname(manifest))
                key = tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[._]", ver))
                if ext_root not in newest or key > newest[ext_root][0]:
                    newest[ext_root] = (key, manifest)
            for _, manifest in sorted(newest.values(), key=lambda v: v[1]):
                data = load_json(manifest)
                if not isinstance(data, dict):
                    continue
                name = str(data.get("name", ""))
                if name.startswith("__MSG_"):
                    name = self._ext_locale_name(os.path.dirname(manifest), name) or name
                if not is_ai_name(name):
                    continue
                perms = list(data.get("permissions", [])) + list(data.get("host_permissions", []))
                for cs in data.get("content_scripts", []) or []:
                    perms += cs.get("matches", [])
                self.agent("extension", name, manifest, f"{browser} extension")
                broad = [p for p in perms if p in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")]
                if broad:
                    self.finding(
                        "MEDIUM", f"AI extension can read every website: {name}", manifest,
                        "It has permission to see and change content on all sites, including "
                        "your email, bank, and work tools.",
                        "Remove it if you don't use it, or set Site access to 'On click' in "
                        f"{browser}'s extension settings.")

    def _ext_locale_name(self, ext_dir, msg):
        key = msg[6:-2]
        for loc in ("en", "en_US"):
            data = load_json(os.path.join(ext_dir, "_locales", loc, "messages.json"))
            if isinstance(data, dict):
                for k, v in data.items():
                    if k.lower() == key.lower() and isinstance(v, dict):
                        return v.get("message")
        return None

    # ---- map: MCP servers and agent permissions

    def scan_configs(self):
        for owner, rel in MCP_CONFIGS:
            path = self.h(rel)
            if not os.path.isfile(path):
                continue
            text = read_text(path) or ""
            data = load_json(path) if path.endswith(".json") else None

            servers = {}
            if isinstance(data, dict):
                servers.update(self._collect_servers(data))
                # Claude Code keeps per-project servers under "projects"
                for proj, pdata in (data.get("projects") or {}).items():
                    if isinstance(pdata, dict):
                        for n, s in self._collect_servers(pdata).items():
                            servers[f"{n} (project: {self.short(proj)})"] = s
                self._check_agent_permissions(owner, path, data)

            for name, cfg in servers.items():
                self.agent("mcp", name, path, f"MCP server in {owner}")
                self._check_server(owner, name, cfg, path)

            secrets = find_secrets(text)
            for label, val in secrets:
                sev = "HIGH"
                why = (f"A {label} is saved in plain text in {owner}'s config. Any app or "
                       "malware that can read your files can steal it and run up charges "
                       "or access your accounts.")
                if world_readable(path):
                    why += " This file is also readable by every user on this computer."
                self.finding(sev, f"{label} in plain text ({mask(val)})", path, why,
                             "Rotate the key, then load it from your password manager or the "
                             "macOS Keychain instead of pasting it into the config.")

    def _collect_servers(self, data):
        found = {}
        for key in ("mcpServers", "servers", "mcp_servers"):
            block = data.get(key)
            if isinstance(block, dict):
                for n, s in block.items():
                    if isinstance(s, dict):
                        found[n] = s
        mcp = data.get("mcp")
        if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
            for n, s in mcp["servers"].items():
                if isinstance(s, dict):
                    found[n] = s
        return found

    def _check_server(self, owner, name, cfg, path):
        cmd = str(cfg.get("command", ""))
        args = [str(a) for a in (cfg.get("args") or [])]
        url = str(cfg.get("url", "") or cfg.get("serverUrl", ""))
        full = " ".join([cmd] + args)

        # remote endpoints: in the url field, or passed to a proxy like mcp-remote
        urls = [url] if url else []
        urls += [a for a in args if re.match(r"https?://", a, re.I)]
        seen_hosts = set()
        for u in urls:
            host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split("@")[-1]
            hostname = host.rsplit(":", 1)[0].strip("[]").lower()
            if hostname in ("localhost", "127.0.0.1", "::1") or hostname.endswith(".localhost"):
                continue
            if u.lower().startswith("http://"):
                self.finding("HIGH", f"MCP server '{name}' talks to the internet without encryption",
                             path, f"It connects to {u} over http, so anyone on your network "
                             "could read or change what the agent sends and receives.",
                             "Switch to the https version of this server, or remove it.")
            if hostname and hostname not in seen_hosts:
                seen_hosts.add(hostname)
                self.finding("LOW", f"MCP server '{name}' sends data to an outside server ({hostname})",
                             path, "Whatever your agent passes to this server's tools (file "
                             f"contents, messages, search text) leaves your computer and goes to {hostname}.",
                             "Keep it only if you trust who runs that server, and don't use its "
                             "tools on private files or accounts.")

        # unpinned packages pulled fresh every launch
        runner = os.path.basename(cmd)
        if runner in ("npx", "bunx", "uvx", "pnpx") or (runner == "pnpm" and "dlx" in args):
            pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx",)]
            pkg = pkgs[0] if pkgs else "?"
            pinned = bool(re.search(r"@\d", pkg)) or ("==" in pkg)
            if not pinned:
                sep = "==" if runner == "uvx" else "@"
                have = self._cached_version(pkg) if sep == "@" else None
                if have:
                    fix = f"Pin the version you already have: replace '{pkg}' with '{pkg}@{have}'."
                else:
                    look = f"pip index versions {pkg}" if sep == "==" else f"npm view {pkg} version"
                    fix = (f"Pin an exact version: run `{look}`, check it, then use "
                           f"'{pkg}{sep}<that version>'.")
                self.finding(
                    "MEDIUM", f"MCP server '{name}' auto-installs the latest code every launch",
                    path, f"`{full[:80]}` downloads '{pkg}' fresh each time. If that package is "
                    "ever hijacked, the new code runs with your agent's access, with no review.",
                    fix)

        # broad filesystem access
        for a in args:
            p = os.path.expanduser(a)
            if not os.path.isabs(p):
                continue
            norm = os.path.normpath(p)
            if norm in ("/", self.home, "/Users", "/home"):
                self.finding("HIGH", f"MCP server '{name}' can access your entire {'drive' if norm == '/' else 'home folder'}",
                             path, f"It was given {self.short(norm) or norm}, which includes SSH keys, "
                             "browser data, documents, and every saved password file.",
                             "Give it only the project folders it actually needs.")
                break
            for s in SENSITIVE_PATHS:
                if norm == self.h(s) or norm.startswith(self.h(s) + os.sep):
                    self.finding("HIGH", f"MCP server '{name}' can read a sensitive folder",
                                 path, f"It has access to {self.short(norm)}, where keys and "
                                 "credentials live.", "Remove that folder from its arguments.")
                    break

        # env vars with real-looking secret values
        env = cfg.get("env") or {}
        if isinstance(env, dict):
            for k, v in env.items():
                v = str(v)
                if SECRET_NAME.search(k) and v and not v.startswith(("${", "$", "op://", "<", "YOUR", "your")) \
                        and not find_secrets(v) and len(v) >= 12:
                    self.finding("MEDIUM", f"MCP server '{name}' stores {k} in plain text",
                                 path, "A credential is pasted directly into the config "
                                 f"({mask(v)}).", "Reference it from your Keychain or an "
                                 "environment variable instead.")

        # servers whose whole job is running commands
        if re.search(r"(shell|terminal|exec|command|bash|desktop-commander)", (name + " " + full).lower()):
            self.finding("MEDIUM", f"MCP server '{name}' can run commands on your computer",
                         path, "Shell access means anything the agent is tricked into doing "
                         "(for example by a poisoned webpage or file) can run as you.",
                         "Keep approval prompts on for this server, and remove it when not in use.")

    def _cached_version(self, pkg):
        """Version of an npm package already in the local npx cache, or None."""
        best = None
        for pj in glob.glob(os.path.join(self.h(".npm/_npx"), "*", "node_modules", pkg, "package.json")):
            data = load_json(pj)
            v = str(data.get("version", "")) if isinstance(data, dict) else ""
            if re.match(r"^\d+\.\d+\.\d+$", v):
                key = tuple(int(x) for x in v.split("."))
                if best is None or key > best[0]:
                    best = (key, v)
        return best[1] if best else None

    def _check_agent_permissions(self, owner, path, data):
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        mode = str(perms.get("defaultMode", "") or data.get("defaultMode", ""))
        if mode == "bypassPermissions" or data.get("dangerouslySkipPermissions") is True:
            self.finding("HIGH", f"{owner} is set to skip all permission prompts", path,
                         "The agent can edit files and run commands without asking you first.",
                         "Turn approval prompts back on and allow-list only safe commands.")
        allow = perms.get("allow") or []
        if isinstance(allow, list):
            wide = [a for a in allow if str(a).strip() in ("Bash", "Bash(*)", "Bash(*:*)", "*")]
            if wide:
                self.finding("HIGH", f"{owner} may run any shell command without asking", path,
                             f"Its allow list includes {', '.join(map(str, wide))}.",
                             "Replace it with specific commands, like Bash(npm test).")
        # Gemini / generic "yolo" flags
        for key in ("autoAccept", "yolo", "yoloMode"):
            if data.get(key) is True:
                self.finding("HIGH", f"{owner} auto-approves actions ({key})", path,
                             "The agent acts without asking you first.",
                             f"Set {key} to false.")
        # Codex approval policy
        if str(data.get("approval_policy", data.get("approvalPolicy", ""))).lower() == "never":
            self.finding("HIGH", f"{owner} never asks for approval", path,
                         "The agent runs commands without checking with you.",
                         "Set approval policy to 'on-request'.")

    # ---- map: keys in shell profiles

    def scan_shell_profiles(self):
        for rel in SHELL_PROFILES:
            path = self.h(rel)
            text = read_text(path)
            if not text:
                continue
            for label, val in find_secrets(text):
                self.finding("MEDIUM", f"{label} in your shell profile ({mask(val)})", path,
                             "Every program you start from the terminal, including AI agents "
                             "and anything they run, can read this key.",
                             "Rotate it, store it in the macOS Keychain, and load it only when needed.")

    # ---- map: local model servers exposed to the network

    def scan_local_servers(self):
        if not self.check_live:
            return
        ports = {11434: "Ollama", 1234: "LM Studio", 8080: "llama.cpp server", 1337: "Jan"}
        listeners = self._listeners()
        for port, app in ports.items():
            addrs = listeners.get(port, set())
            exposed = [a for a in addrs if a in ("*", "0.0.0.0", "::", "[::]")]
            if addrs:
                self.agent("server", app, f"port {port}", "local AI server listening")
            if exposed:
                self.finding("HIGH", f"{app} is open to everyone on your network", f"port {port}",
                             f"It listens on all network interfaces, so anyone on the same "
                             "Wi-Fi (a coffee shop, school, or airport) can use your models "
                             "and see what they're doing.",
                             f"Bind it to 127.0.0.1 only (for Ollama: unset OLLAMA_HOST or set "
                             "it to 127.0.0.1).")

    def _listeners(self):
        result = {}
        cmds = [["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], ["ss", "-ltnH"]]
        for cmd in cmds:
            if not shutil.which(cmd[0]):
                continue
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
            except (OSError, subprocess.SubprocessError):
                continue
            for m in re.finditer(r"(\*|\[?[0-9a-f:.]+\]?|[0-9.]+):(\d+)\b", out):
                addr, port = m.group(1), int(m.group(2))
                result.setdefault(port, set()).add(addr.strip("[]") if addr != "[::]" else "::")
            if result:
                break
        return result

    # ---- run

    def run(self):
        self.scan_apps()
        self.scan_clis()
        self.scan_processes()
        self.scan_extensions()
        self.scan_configs()
        self.scan_shell_profiles()
        self.scan_local_servers()
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
        return self


# ---------------------------------------------------------------- output

def color(enabled):
    if not enabled:
        return {k: "" for k in ("r", "y", "g", "b", "d", "c", "x")}
    return {"r": "\033[31m", "y": "\033[33m", "g": "\033[32m", "b": "\033[1m",
            "d": "\033[2m", "c": "\033[36m", "x": "\033[0m"}


def print_report(sc, use_color):
    C = color(use_color)
    sev_c = {"HIGH": C["r"], "MEDIUM": C["y"], "LOW": C["c"], "INFO": C["d"]}
    print(f"{C['b']}ai-guardian {VERSION}{C['x']} - what AI is on this machine, and what can it touch?\n")

    labels = [("app", "AI apps"), ("cli", "Command-line agents"), ("process", "Running now"),
              ("server", "Local AI servers"), ("mcp", "MCP servers (agent plugins)"),
              ("extension", "AI browser extensions")]
    if not sc.agents:
        print(f"  {C['g']}No AI agents found.{C['x']}\n")
    for kind, label in labels:
        items = [a for a in sc.agents if a["type"] == kind]
        if not items:
            continue
        print(f"  {C['b']}{label} ({len(items)}){C['x']}")
        for a in items:
            print(f"    • {a['name']:<28} {C['d']}{a['detail']} - {a['where']}{C['x']}")
        print()

    counts = {s: sum(1 for f in sc.findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW")}
    if not sc.findings:
        print(f"  {C['g']}{C['b']}No risky setups found.{C['x']}")
    else:
        print(f"  {C['b']}Risks ({len(sc.findings)}){C['x']}\n")
        for f in sc.findings:
            sc_ = sev_c.get(f["severity"], "")
            print(f"  {sc_}{f['severity']:<6}{C['x']} {C['b']}{f['title']}{C['x']}")
            print(f"         {C['d']}{f['where']}{C['x']}")
            print(f"         Why: {f['why']}")
            print(f"         Fix: {f['fix']}\n")
    live = f", {len(sc.running)} running now" if sc.check_live else ""
    print(f"  {C['b']}Summary:{C['x']} {len(sc.installed)} AI agent(s) installed{live} · "
          f"{C['r']}{counts['HIGH']} high{C['x']}, {C['y']}{counts['MEDIUM']} medium{C['x']}, "
          f"{C['c']}{counts['LOW']} low{C['x']} risk(s)")
    print(f"  {C['d']}Read-only scan. Secrets are masked. Nothing left this computer.{C['x']}")


def to_json(sc):
    return {
        "tool": "ai-guardian", "version": VERSION, "host": socket.gethostname(),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "agents": len(sc.installed),
            "running": len(sc.running),
            "high": sum(1 for f in sc.findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in sc.findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in sc.findings if f["severity"] == "LOW"),
        },
        "agents": sc.agents, "findings": sc.findings,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find the AI agents on your machine and what they can touch.")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--home", default="~", help="home folder to scan (default: yours)")
    ap.add_argument("--no-live", action="store_true", help="skip running-process and network checks")
    ap.add_argument("--fail-on", choices=["high", "medium", "none"], default="high",
                    help="exit 1 when risks at this level are found (default: high)")
    ap.add_argument("-v", "--version", action="version", version=f"ai-guardian {VERSION}")
    a = ap.parse_args(argv)

    sc = Scanner(a.home, check_live=not a.no_live).run()
    if a.json:
        print(json.dumps(to_json(sc), indent=2))
    else:
        print_report(sc, sys.stdout.isatty() and not os.environ.get("NO_COLOR"))

    levels = {"high": ("HIGH",), "medium": ("HIGH", "MEDIUM"), "none": ()}[a.fail_on]
    return 1 if any(f["severity"] in levels for f in sc.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
