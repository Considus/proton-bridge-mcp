#!/usr/bin/env python3
"""Tests for the Proton Bridge MCP server.

None of these need Proton Bridge running or a real account. They cover the
parts that are easy to break and expensive to get wrong: attachment
classification, the write sandbox, and the anti-exfiltration rules.

    python3 -m unittest discover -s tests -v
"""

import email
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PY = os.path.join(HERE, "server.py")


def build_message():
    """A message carrying one real document, one inline image and a PGP key."""
    msg = EmailMessage()
    msg["From"] = "Sender <sender@example.com>"
    msg["To"] = "me@example.com"
    msg["Subject"] = "Invoice attached"
    msg.set_content("Body text. Contact billing@evil.example for questions.")
    msg.add_attachment(b"%PDF-1.4 fake", maintype="application",
                       subtype="pdf", filename="invoice.pdf")
    inline = EmailMessage()
    inline.set_content(b"\x89PNG fake", maintype="image", subtype="png")
    inline.add_header("Content-Disposition", "inline", filename="logo.png")
    inline.add_header("Content-ID", "<logo>")
    msg.attach(inline)
    msg.add_attachment(b"-----BEGIN PGP PUBLIC KEY BLOCK-----",
                       maintype="application", subtype="pgp-keys",
                       filename="publickey.asc")
    return msg.as_bytes()


class Attachments(unittest.TestCase):
    def test_documents_are_separated_from_noise(self):
        items = server._iter_attachments(build_message())
        kinds = {a["filename"]: a["kind"] for a in items}
        self.assertEqual(kinds.get("invoice.pdf"), "document")
        self.assertEqual(kinds.get("logo.png"), "inline")
        self.assertEqual(kinds.get("publickey.asc"), "pgp")

    def test_body_parts_are_not_attachments(self):
        names = [a["filename"] for a in server._iter_attachments(build_message())]
        self.assertEqual(len(names), 3, "body text must not count as an attachment")

    def test_body_text_is_still_extracted(self):
        self.assertIn("Body text", server._extract_body(build_message()))


class WriteSandbox(unittest.TestCase):
    """MCP servers get no sandbox from the host, so this IS the sandbox."""

    def test_absolute_path_outside_root_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_dest("/tmp/somewhere-else")

    def test_parent_traversal_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_dest("../../etc")

    def test_subdirectory_is_allowed(self):
        got = server._resolve_dest("sub/dir")
        self.assertTrue(got.startswith(os.path.realpath(server.ATTACH_DIR)))

    def test_filename_cannot_escape_or_become_a_dotfile(self):
        got = server._safe_name("../../../.ssh/authorized_keys", "7")
        self.assertNotIn("/", got)
        self.assertNotIn("..", got.replace("_", ""))
        self.assertTrue(got.startswith("uid7_"))

    def test_control_characters_are_stripped(self):
        self.assertNotIn("\n", server._safe_name("bad\nname.pdf", "1"))

    def test_empty_filename_still_produces_something(self):
        self.assertEqual(server._safe_name("", "3"), "uid3_attachment.bin")


class Exfiltration(unittest.TestCase):
    """Addresses seen only in untrusted content must not be mailable, and no
    tool parameter may override that."""

    def setUp(self):
        server._CORRESPONDENTS.clear()
        server._TAINTED.clear()
        os.environ.pop("PROTON_ALLOWED_RECIPIENTS", None)

    def test_header_address_is_allowed(self):
        msg = email.message_from_bytes(build_message())
        server._note_headers(msg)
        server._check_recipients("sender@example.com")  # must not raise

    def test_body_address_is_blocked(self):
        msg = email.message_from_bytes(build_message())
        server._note_headers(msg)
        server._taint_text(server._extract_body(build_message()))
        with self.assertRaises(server.ToolError):
            server._check_recipients("billing@evil.example")

    def test_blocked_even_when_named_in_a_display_name(self):
        server._taint_text("write to attacker@evil.example")
        with self.assertRaises(server.ToolError):
            server._check_recipients("Someone <attacker@evil.example>")

    def test_allowlist_is_the_only_override(self):
        server._taint_text("attacker@evil.example")
        os.environ["PROTON_ALLOWED_RECIPIENTS"] = "attacker@evil.example"
        server._check_recipients("attacker@evil.example")  # must not raise

    def test_unknown_address_is_not_blocked(self):
        server._check_recipients("someone-new@example.com")  # must not raise


class SenderAllowlist(unittest.TestCase):
    """from_address must not be pointable at an arbitrary address."""

    def setUp(self):
        self._user, self._alias = server.USER, server.ALIAS_FROM
        server.USER, server.ALIAS_FROM = "me@example.com", "me@pm.example"
        os.environ.pop("PROTON_ALLOWED_SENDERS", None)

    def tearDown(self):
        server.USER, server.ALIAS_FROM = self._user, self._alias
        os.environ.pop("PROTON_ALLOWED_SENDERS", None)

    def test_configured_user_is_allowed(self):
        server._check_sender("me@example.com")

    def test_alias_owner_is_allowed(self):
        server._check_sender("me@pm.example")

    def test_arbitrary_address_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._check_sender("ceo@victim.example")

    def test_display_name_does_not_smuggle_it_through(self):
        with self.assertRaises(server.ToolError):
            server._check_sender("Me <ceo@victim.example>")

    def test_empty_means_default_sender(self):
        server._check_sender("")

    def test_allowlist_widens_it(self):
        os.environ["PROTON_ALLOWED_SENDERS"] = "extra@example.com"
        server._check_sender("extra@example.com")


class UidValidity(unittest.TestCase):
    """A UID only means anything inside one UIDVALIDITY generation."""

    class FakeConn:
        def __init__(self, validity):
            self._v = validity
        def select(self, mailbox, readonly=False):
            return "OK", [b"1"]
        def response(self, name):
            return name, [self._v.encode()]

    def test_matching_validity_passes(self):
        got = server._select_checked(self.FakeConn("111"), "INBOX", "111")
        self.assertEqual(got, "111")

    def test_mismatch_is_refused(self):
        with self.assertRaises(server.ToolError) as cm:
            server._select_checked(self.FakeConn("222"), "INBOX", "111")
        self.assertIn("UIDVALIDITY", str(cm.exception))
        self.assertIn("Nothing was changed", str(cm.exception))

    def test_omitting_it_still_works(self):
        got = server._select_checked(self.FakeConn("333"), "INBOX", None)
        self.assertEqual(got, "333")

    def test_unopenable_folder_raises(self):
        class Bad(self.FakeConn):
            def select(self, mailbox, readonly=False):
                return "NO", [b"nope"]
        with self.assertRaises(server.ToolError):
            server._select_checked(Bad("1"), "Nope", None)


class Config(unittest.TestCase):
    def test_env_beats_settings_file(self):
        tmp = tempfile.mkdtemp()
        settings = os.path.join(tmp, "settings.json")
        with open(settings, "w") as f:
            json.dump({"PROTON_USER": "from-file@example.com"}, f)
        old = server.SETTINGS_FILE
        try:
            server.SETTINGS_FILE = settings
            server._SETTINGS = server._load_settings()
            self.assertEqual(server._cfg("PROTON_USER"), "from-file@example.com")
            os.environ["PROTON_USER"] = "from-env@example.com"
            self.assertEqual(server._cfg("PROTON_USER"), "from-env@example.com")
        finally:
            os.environ.pop("PROTON_USER", None)
            server.SETTINGS_FILE = old
            server._SETTINGS = server._load_settings()

    def test_sender_domain_is_derived_not_hardcoded(self):
        self.assertEqual(server._sender_domain("a@b.example"), "b.example")


def rpc(requests, env=None):
    """Drive the server over stdio the way a real MCP client does."""
    e = dict(os.environ)
    e.setdefault("PROTON_USER", "test@example.com")
    e.update(env or {})
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    out = subprocess.run([sys.executable, SERVER_PY], input=payload,
                         capture_output=True, text=True, timeout=30, env=e).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}}


class Protocol(unittest.TestCase):
    def test_initialize_and_list_tools(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        init = [m for m in msgs if m.get("id") == 1][0]
        self.assertEqual(init["result"]["serverInfo"]["name"], "proton-mail")
        tools = [t["name"] for m in msgs if m.get("id") == 2
                 for t in m["result"]["tools"]]
        for expected in ("list_folders", "search_mail", "read_message",
                         "list_attachments", "read_attachment", "find_thread",
                         "send", "forward"):
            self.assertIn(expected, tools)

    def test_unknown_method_does_not_kill_the_server(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "nope"},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}])
        self.assertTrue(any(m.get("id") == 3 and "result" in m for m in msgs))

    def test_tools_list_works_before_setup(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
                   env={"PROTON_USER": "", "PROTON_SETTINGS_FILE": os.devnull})
        self.assertTrue(any(m.get("id") == 2 and m["result"]["tools"] for m in msgs))

    def test_unconfigured_call_explains_itself(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "list_folders", "arguments": {}}}],
                   env={"PROTON_USER": "", "PROTON_SETTINGS_FILE": os.devnull})
        res = [m for m in msgs if m.get("id") == 2][0]["result"]
        self.assertTrue(res.get("isError"))
        self.assertIn("PROTON_USER", res["content"][0]["text"])

    def test_readonly_removes_every_mutating_tool(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
                   env={"PROTON_READONLY": "1"})
        tools = [t["name"] for m in msgs if m.get("id") == 2
                 for t in m["result"]["tools"]]
        for gone in ("send", "forward", "move_to_folder", "create_mailbox",
                     "apply_label", "mark", "save_attachment", "create_draft"):
            self.assertNotIn(gone, tools)
        self.assertIn("read_message", tools)

    def test_send_refuses_without_confirmation(self):
        msgs = rpc([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "send", "arguments": {
                               "to": "a@b.example", "subject": "x",
                               "body": "y", "confirmed": False}}}])
        res = [m for m in msgs if m.get("id") == 2][0]["result"]
        self.assertTrue(res.get("isError"))
        self.assertIn("confirmed", res["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
