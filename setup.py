#!/usr/bin/env python3
"""
Proton Bridge MCP — guided local setup.

Starts a web UI on 127.0.0.1 (random port, single-session token), collects
your Bridge mailbox details, verifies them against Bridge, stores the passwords
in the operating system's secure credential store, writes the MCP client
config, and shuts itself down.

Nothing leaves this computer. The password is never written to disk in plaintext,
never logged, and never echoed back into the page.

    python3 setup.py
"""

import hmac
import html
import http.server
import imaplib
import json
import os
import secrets
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_PY = os.path.join(HERE, "server.py")
VENV_PY = os.path.join(HERE, ".venv",
                       "Scripts" if os.name == "nt" else "bin",
                       "python.exe" if os.name == "nt" else "python")
BRAND_SVG = os.path.join(HERE, "assets", "considus-icon.svg")

TOKEN = secrets.token_urlsafe(32)
KEYCHAIN_SVC = "proton-bridge-imap"
SMTP_KEYCHAIN_SVC = "proton-bridge-smtp"
IDLE_TIMEOUT = 900  # the UI self-destructs after 15 minutes

def _app_support():
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support")
    if os.name == "nt":
        return os.environ.get("APPDATA", os.path.expanduser("~/AppData/Roaming"))
    return os.path.expanduser("~/.config")


def _p(*parts):
    return os.path.expanduser(os.path.join(*parts))


# setup.py never edits any AI client's config. It stores non-secret settings
# here (the server reads them) and hands the user a prompt to install the server
# into whatever client they use. One path for every client, nothing to go stale.
SETTINGS_FILE = os.path.join(HERE, "settings.json")

EXISTING = None  # populated at startup; drives update mode


# ---------------------------------------------------------------------------
# Brand mark
# ---------------------------------------------------------------------------
def brand_mark():
    """Inline the real Considus icon if present; otherwise omit it entirely
    rather than substitute an invented mark."""
    try:
        with open(BRAND_SVG, "r", encoding="utf-8") as f:
            svg = f.read()
        i = svg.find("<svg")
        if i < 0:
            return ""
        svg = svg[i:]
        # Affinity exports an xmlns:serif attribute. It is an XML namespace, never
        # fetched — but a privacy tool shouldn't ship a stray http:// at all.
        return svg.replace(' xmlns:serif="http://www.serif.com/"', "") \
                  .replace(' xmlns:xlink="http://www.w3.org/1999/xlink"', "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Credential + config writing
# ---------------------------------------------------------------------------
def store_password(user, password, service=KEYCHAIN_SVC):
    """Store in the OS credential store — Keychain on macOS, Credential Manager
    on Windows, Secret Service/KWallet on Linux. Never touches disk in plaintext.

    keyring is preferred wherever it's importable because it calls the platform
    credential API directly, keeping the password out of the process argument
    list. Stock macOS has no keyring, so we fall back to the `security` tool;
    its `-w` places the secret in argv for the lifetime of that one short-lived
    call — a known, accepted trade-off on a single-user machine, and the reason
    keyring is tried first."""
    try:
        import keyring
        keyring.set_password(service, user, password)
        return "secure credential store"
    except Exception:
        pass
    if sys.platform == "darwin":
        r = subprocess.run(
            ["security", "add-generic-password", "-U", "-a", user,
             "-s", service, "-w", password],
            capture_output=True, text=True)
        if r.returncode == 0:
            return "secure credential store"
        raise RuntimeError("Could not save to the credential store: %s"
                           % (r.stderr.strip() or r.returncode))
    raise RuntimeError(
        "No secure credential store available on this computer. Install "
        "support with `pip install keyring`, or set PROTON_BRIDGE_PASSWORD "
        "in your MCP config instead.")


def existing_config():
    """Previous non-secret settings, so re-running opens in update mode."""
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if data.get("PROTON_USER") else None
    except Exception:
        return None


def lookup_password(account, service):
    """Read a stored credential so a blank field can mean 'keep current'.
    Used ONLY to re-verify server-side — never returned to the browser."""
    if not account:
        return None
    if sys.platform == "darwin":
        try:
            r = subprocess.run(
                ["security", "find-generic-password", "-a", account,
                 "-s", service, "-w"], capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.rstrip("\n")
        except Exception:
            pass
    try:
        import keyring
        return keyring.get_password(service, account)
    except Exception:
        return None


_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def _verify_ctx(host):
    """Mirror the running server's TLS policy: skip verification only on
    loopback, where Bridge's self-signed certificate can't be checked against a
    public CA. A real remote provider is verified properly, so setup can't hand
    the mailbox password to a man in the middle."""
    ctx = ssl.create_default_context()
    if (host or "").strip().lower() in _LOOPBACK:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _sec_mode(mode, port):
    """auto -> implicit TLS on the secure ports, STARTTLS elsewhere."""
    mode = (mode or "auto").strip().lower()
    if mode == "auto":
        return "ssl" if int(port) in (993, 465) else "starttls"
    return mode


def verify(iuser, ipass, ihost, iport, suser, spass, shost, sport,
           isec="auto", ssec="auto"):
    """Prove both sets of details work before we store anything. IMAP and SMTP
    are checked independently — Bridge shares credentials today, but nothing
    here assumes it will forever. TLS is verified for real remote hosts and only
    skipped on loopback, matching the server; the chosen security mode decides
    implicit TLS versus STARTTLS."""
    imode = _sec_mode(isec, iport)
    ictx = _verify_ctx(ihost)
    try:
        if imode == "ssl":
            c = imaplib.IMAP4_SSL(ihost, int(iport), ssl_context=ictx, timeout=15)
        else:
            c = imaplib.IMAP4(ihost, int(iport), timeout=15)
            c.starttls(ictx)
        c.login(iuser, ipass)
        n = len(c.list()[1] or [])
        c.logout()
    except Exception as e:
        raise RuntimeError("IMAP check failed on %s:%s — %s" % (ihost, iport, e))
    smode = _sec_mode(ssec, sport)
    sctx = _verify_ctx(shost)
    try:
        if smode == "ssl":
            s = smtplib.SMTP_SSL(shost, int(sport), timeout=15, context=sctx)
        else:
            s = smtplib.SMTP(shost, int(sport), timeout=15)
            s.ehlo(); s.starttls(context=sctx); s.ehlo()
        s.login(suser, spass)
        s.quit()
    except Exception as e:
        raise RuntimeError("SMTP check failed on %s:%s — %s" % (shost, sport, e))
    return n


def server_command():
    return VENV_PY if os.path.exists(VENV_PY) else sys.executable


def mcp_settings(iuser, alias_from, ihost, iport, suser, shost, sport,
                 isec="auto", ssec="auto"):
    """Non-secret settings the server reads from settings.json."""
    v = {"PROTON_USER": iuser,
         "PROTON_IMAP_HOST": ihost, "PROTON_IMAP_PORT": str(iport),
         "PROTON_SMTP_HOST": shost, "PROTON_SMTP_PORT": str(sport)}
    if isec and isec != "auto":
        v["PROTON_IMAP_SECURITY"] = isec
    if ssec and ssec != "auto":
        v["PROTON_SMTP_SECURITY"] = ssec
    if suser and suser != iuser:
        v["PROTON_SMTP_USER"] = suser
    if alias_from:
        v["PROTON_ALIAS_FROM"] = alias_from
    return v


def save_settings(values):
    """Write non-secret settings only. Passwords live in the credential store."""
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(values, f, indent=2)
    os.replace(tmp, SETTINGS_FILE)
    try:
        os.chmod(SETTINGS_FILE, 0o600)
    except OSError:
        pass
    return SETTINGS_FILE


def install_prompt(name="proton-mail"):
    """Self-contained prompt the user pastes into ANY AI to install the server
    into whatever client that AI runs in. Contains no secret and no settings."""
    return """I have a local MCP server on this computer and I'd like you to register it with \
the MCP client you are running inside.

Server details:
  name    = %s
  command = %s
  args    = ["%s"]

Please:
1. Work out where THIS client stores its MCP server configuration on this machine.
2. Make a backup of that file before changing it.
3. Add the server above using whichever key this client expects, for example:
   - "mcpServers"      (Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI)
   - "servers"         (VS Code / GitHub Copilot agent mode)
   - "context_servers" (Zed)
   - a [mcp_servers.%s] section for TOML configs (OpenAI Codex CLI)
4. No environment variables or secrets are needed. The server reads its own settings file, \
and takes the Proton Bridge password from this computer's secure credential store. Never put \
a password in the config.
5. Tell me which file you changed and whether I need to restart the app.

If you cannot write files, just tell me the exact file path and the exact snippet to paste, \
and I will do it myself.""" % (name, server_command(), SERVER_PY, name)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
CSS = """
:root{
  --ink:#0F0E0C; --dusk:#1C1A16; --starlight:#ECF1F5; --haze:#9AADB8;
  --slate:#4C5E6B; --cirrus:#EEF3F7; --drift:#D0DAE2;
  --stellar:#A0DCEE; --orbit:#1A9ABE; --anchor:#15788F;
  --bg:var(--cirrus); --surface:#ffffff; --edge:rgba(0,0,0,0.08);
  --text:var(--ink); --muted:var(--slate); --accent:var(--orbit); --cta:var(--anchor);
  --serif:'Cormorant Garamond',Georgia,'Times New Roman',serif;
  --sans:'DM Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
}
@media (prefers-color-scheme:dark){
  :root{ --bg:var(--ink); --surface:var(--dusk); --edge:rgba(255,255,255,0.06);
         --text:var(--starlight); --muted:var(--haze); --accent:var(--stellar); --cta:var(--orbit); }
}
*{box-sizing:border-box}
/* Readability, matching considus.com: functional text is DM Sans 400 with
   0.04em tracking and 1.75 leading — Light 300 is display-only. */
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
     font-weight:400;font-size:15px;line-height:1.75;-webkit-font-smoothing:antialiased;
     padding:48px 24px 80px;}
.wrap{max-width:920px;margin:0 auto}
header{display:flex;align-items:center;gap:14px;margin-bottom:8px}
header svg{width:34px;height:34px;flex:none}
.word{font-family:var(--serif);font-weight:300;font-size:34px;letter-spacing:-0.01em;line-height:1}
h1{font-family:var(--serif);font-weight:300;font-size:40px;line-height:1.15;margin:26px 0 10px}
.lede{color:var(--muted);max-width:62ch;margin:0 0 6px;font-size:0.95rem;line-height:1.75}
.note{color:var(--muted);font-size:0.87rem;line-height:1.75;max-width:70ch}
.cards{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin:34px 0 10px}
@media (max-width:720px){.cards{grid-template-columns:1fr}}
.card{background:var(--surface);border:1px solid var(--edge);border-radius:18px;padding:26px 26px 8px}
.card h2{font-family:var(--sans);font-weight:500;font-size:0.8rem;margin:0 0 22px;
         letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.row{padding:0 0 14px;margin-bottom:14px;border-bottom:1px solid var(--edge)}
.row:last-child{border-bottom:none}
label{display:block;font-size:0.68rem;font-weight:500;letter-spacing:.12em;
      text-transform:uppercase;color:var(--muted);margin-bottom:8px;line-height:1.4}
select{width:100%;background:transparent;border:none;outline:none;color:var(--text);font-family:var(--sans);font-size:1rem;font-weight:400;padding:3px 0}
input{width:100%;background:transparent;border:none;outline:none;color:var(--text);
      font-family:var(--sans);font-size:1rem;font-weight:400;letter-spacing:.01em;padding:3px 0}
input::placeholder{color:var(--muted);opacity:.55;font-weight:400}
input:focus{border-bottom:1px solid var(--accent);margin-bottom:-1px}
.fixed{color:var(--muted);font-size:1rem;font-weight:400;padding:3px 0}
.extras{background:var(--surface);border:1px solid var(--edge);border-radius:18px;
        padding:26px;margin-top:22px}
.check{display:flex;gap:11px;align-items:flex-start;margin-top:18px;color:var(--muted);font-size:0.87rem;line-height:1.7}
.check input{width:auto;margin-top:3px}
button{margin-top:28px;background:var(--cta);color:#fff;border:none;border-radius:11px;
       padding:15px 32px;font-family:var(--sans);font-size:0.9rem;font-weight:400;
       letter-spacing:.04em;cursor:pointer}
button:hover{filter:brightness(1.09)}
.err{background:#7f1d1d;color:#fff;border-radius:11px;padding:16px 18px;margin:22px 0;font-size:0.9rem;line-height:1.7}
.ok{border-left:3px solid var(--accent);padding-left:18px;margin:22px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;
     background:var(--bg);border:1px solid var(--edge);border-radius:7px;padding:2px 6px}
ul{padding-left:20px;color:var(--muted);font-size:0.9rem} li{margin:7px 0}\n.sub{font-family:var(--sans);font-weight:500;font-size:0.72rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:34px 0 12px}
pre{overflow-x:auto;white-space:pre-wrap;background:var(--bg);border:1px solid var(--edge);border-radius:11px;padding:18px;font-size:0.82rem;line-height:1.6;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre code{background:none;border:none;padding:0;line-height:1.6}
"""


def page(body, title="Considus · Proton Bridge setup"):
    return """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>%s</style></head><body><div class="wrap">
<header>%s<span class="word">Considus</span></header>%s</div></body></html>""" % (
        html.escape(title), CSS, brand_mark(), body)


def row(label, name, value="", placeholder="", kind="text"):
    return """<div class="row"><label for="%s">%s</label>
<input id="%s" name="%s" type="%s" value="%s" placeholder="%s" autocomplete="off"
 spellcheck="false" %s></div>""" % (
        name, html.escape(label), name, name, kind, html.escape(value),
        html.escape(placeholder), "required" if kind != "text" or name else "")


def select_row(label, name, options, value=""):
    opts = "".join(
        '<option value="%s"%s>%s</option>'
        % (v, " selected" if v == value else "", html.escape(t))
        for v, t in options)
    return ('<div class="row"><label for="%s">%s</label>'
            '<select id="%s" name="%s">%s</select></div>'
            % (name, html.escape(label), name, name, opts))


def fixed_row(label, value):
    return """<div class="row"><label>%s</label><div class="fixed">%s</div></div>""" % (
        html.escape(label), html.escape(value))


def form_page(error="", existing=None):
    err = '<div class="err">%s</div>' % html.escape(error) if error else ""
    e = existing or {}
    updating = bool(e.get("PROTON_USER"))
    pw_ph = "leave blank to keep current" if updating else "from Bridge"
    heading = "Update your Bridge settings" if updating else "Connect your ProtonMail Bridge"
    if updating:
        lede = ('<p class="lede">Your current settings are filled in below. Change only what '
                'you need \u2014 a blank password field keeps the one already stored.</p>')
    else:
        lede = ('<p class="lede">Copy each value from <strong>Proton Mail Bridge \u2192 '
                'Mailbox details</strong>. Bridge currently shows the same username and '
                'password for both, but enter them separately \u2014 they are stored and used '
                'independently, so this keeps working if Proton ever splits them.</p>')
    return page("""
<h1>%s</h1>
%s
<p class="note">Everything stays on this computer. Your passwords go straight into its
secure credential store, and this page shuts down the moment setup completes.</p>
%s
<form method="POST" action="/save?token=%s">
  <div class="cards">
    <div class="card">
      <h2>IMAP</h2>
      %s%s%s%s%s
    </div>
    <div class="card">
      <h2>SMTP</h2>
      %s%s%s%s%s
    </div>
  </div>

  <div class="extras">
    <div class="row">
      <label for="alias_from">Authorised address <span style="text-transform:none;letter-spacing:0">(optional)</span></label>
      <input id="alias_from" name="alias_from" type="text" value="%s" placeholder="you@pm.me"
             autocomplete="off" spellcheck="false">
    </div>
    <p class="note">Emails sent from this address to a reverse-alias are considered as being
    sent from your approved Proton/SimpleLogin mailbox.</p>
  </div>

  <button type="submit">%s</button>
</form>
<p class="note" style="margin-top:26px">%s</p>
""" % (html.escape(heading), lede, err, TOKEN,
       row("Hostname", "imap_host", e.get("PROTON_IMAP_HOST", "127.0.0.1")),
       row("Port", "imap_port", e.get("PROTON_IMAP_PORT", ""), "from Bridge"),
       row("Username", "imap_user", e.get("PROTON_USER", ""), "from Bridge"),
       row("Password", "imap_pass", "", pw_ph, "password"),
       select_row("Security", "imap_security", [('auto', 'Automatic (by port)'), ('starttls', 'STARTTLS'), ('ssl', 'SSL / TLS')], e.get("PROTON_IMAP_SECURITY", "auto")),
       row("Hostname", "smtp_host", e.get("PROTON_SMTP_HOST", "127.0.0.1")),
       row("Port", "smtp_port", e.get("PROTON_SMTP_PORT", ""), "from Bridge"),
       row("Username", "smtp_user",
           e.get("PROTON_SMTP_USER") or e.get("PROTON_USER", ""), "from Bridge"),
       row("Password", "smtp_pass", "", pw_ph, "password"),
       select_row("Security", "smtp_security", [('auto', 'Automatic (by port)'), ('starttls', 'STARTTLS'), ('ssl', 'SSL / TLS')], e.get("PROTON_SMTP_SECURITY", "auto")),
       html.escape(e.get("PROTON_ALIAS_FROM", "")),
       "Save changes" if updating else "Verify and finish setup",
       "Both connections are re-tested before anything is saved."
       if updating else
       "Nothing is pre-filled except the hostname: Bridge assigns its own ports and "
       "credentials, so every value should be read from Bridge rather than assumed. "
       "Both connections are tested before anything is saved."))


def done_page(user, store, mailboxes, settings_path):
    prompt = install_prompt()
    return page("""
<h1>Setup complete</h1>
<div class="ok">
<p><strong>%s</strong> verified against Bridge \u2014 %d mailboxes visible.</p>
<p class="note">Passwords stored in your computer's <strong>%s</strong>. They were never
written to disk in plaintext and never appeared in this page. Your other settings are in
<code>%s</code>, which contains no secrets.</p>
</div>

<h2 class="sub">Last step \u2014 install it in your AI</h2>
<p class="note">Paste this into whichever assistant you want to use the mailbox from
\u2014 Claude, Cursor, Windsurf, Zed, Codex CLI, Gemini CLI, VS Code Copilot, anything.
It works out where that client keeps its own MCP config, so it stays correct as tools change.
No settings or passwords are in it.</p>
<pre id="p">%s</pre>
<button type="button" onclick="navigator.clipboard.writeText(document.getElementById('p').textContent).then(()=>{this.textContent='Copied';setTimeout(()=>this.textContent='Copy prompt',1600)})">Copy prompt</button>
<p class="note" style="margin-top:26px">Run <code>python3 setup.py</code> again to change
anything \u2014 it reopens in update mode. This page has now shut down.</p>
""" % (html.escape(user), mailboxes, html.escape(store),
       html.escape(settings_path), html.escape(prompt)))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ConsidusSetup/1.0"

    def log_message(self, *a):
        pass  # never log — request bodies contain the password

    def _send(self, body, code=200):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        got = (q.get("token") or [""])[0]
        return hmac.compare_digest(got, TOKEN)

    def _host_ok(self):
        """Only answer requests addressed to this machine by name. Closes the
        DNS-rebinding path where a remote page resolves its own domain to
        127.0.0.1 to reach this server; the browser still sends the attacker's
        Host, so it's refused before the token is even considered."""
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip().lower()
        return host in ("", "127.0.0.1", "localhost", "::1", "[::1]")

    def do_GET(self):
        if not self._host_ok():
            self._send(page("<h1>Not authorised</h1>"), 403)
            return
        if not self._authed():
            self._send(page("<h1>Not authorised</h1><p class='lede'>Open the exact link "
                            "printed in your terminal.</p>"), 403)
            return
        self._send(form_page(existing=EXISTING))

    def do_POST(self):
        if not self._host_ok():
            self._send(page("<h1>Not authorised</h1>"), 403)
            return
        if not self._authed():
            self._send(page("<h1>Not authorised</h1>"), 403)
            return
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8"))
        g = lambda k, d="": (form.get(k) or [d])[0].strip()

        user, pw = g("imap_user"), g("imap_pass")
        smtp_user, smtp_pass = g("smtp_user"), g("smtp_pass")
        ihost, iport = g("imap_host"), g("imap_port")
        shost, sport = g("smtp_host"), g("smtp_port")

        # A blank password means "keep the stored one" — but only when the
        # username still matches, otherwise the stored secret belongs elsewhere.
        typed_imap, typed_smtp = bool(pw), bool(smtp_pass)
        if not pw:
            pw = lookup_password(user, KEYCHAIN_SVC)
        if not smtp_pass:
            smtp_pass = (lookup_password(smtp_user, SMTP_KEYCHAIN_SVC)
                         or (pw if smtp_user == user else None))

        missing = [n for n, v in (
            ("IMAP hostname", ihost), ("IMAP port", iport),
            ("IMAP username", user), ("IMAP password", pw),
            ("SMTP hostname", shost), ("SMTP port", sport),
            ("SMTP username", smtp_user), ("SMTP password", smtp_pass)) if not v]
        if missing:
            self._send(form_page(existing=EXISTING, error="Still needed: %s." % ", ".join(missing))); return
        try:
            iport_i, sport_i = int(iport), int(sport)
        except ValueError:
            self._send(form_page(existing=EXISTING, error="Ports must be numbers — copy them from Bridge.")); return

        isec, ssec = g("imap_security", "auto"), g("smtp_security", "auto")
        try:
            mailboxes = verify(user, pw, ihost, iport_i,
                               smtp_user, smtp_pass, shost, sport_i,
                               isec, ssec)
        except RuntimeError as e:
            self._send(form_page(existing=EXISTING, error=str(e))); return

        try:
            store = store_password(user, pw)
            # Always stored separately, so a future split needs no migration.
            store_password(smtp_user, smtp_pass, SMTP_KEYCHAIN_SVC)
            if not (typed_imap or typed_smtp):
                store = "secure credential store (unchanged)"
        except RuntimeError as e:
            self._send(form_page(existing=EXISTING, error=str(e))); return

        settings = mcp_settings(user, g("alias_from"), ihost, iport_i,
                                smtp_user, shost, sport_i, isec, ssec)
        saved_to = save_settings(settings)
        self._send(done_page(user, store, mailboxes, saved_to))
        threading.Thread(target=lambda: (time.sleep(1.5),
                                         self.server.shutdown()), daemon=True).start()


def main():
    if not os.path.exists(SERVER_PY):
        sys.exit("server.py not found next to setup.py — run this from the repo folder.")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    global EXISTING
    EXISTING = existing_config()
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d/?token=%s" % (port, TOKEN)
    print("\n  Considus · Proton Bridge MCP %s" % (
        "settings update" if EXISTING else "setup"))
    print("  Local only — bound to 127.0.0.1, single-session link, shuts down when done.\n")
    print("  %s\n" % url)
    threading.Timer(IDLE_TIMEOUT, httpd.shutdown).start()
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    print("  Setup server stopped.\n")
    os._exit(0)


if __name__ == "__main__":
    main()
