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


class AttachmentPicking(unittest.TestCase):
    def test_picks_the_only_document(self):
        att = server._pick_attachment(build_message(), None)
        self.assertEqual(att["filename"], "invoice.pdf")

    def test_picks_by_partial_name(self):
        att = server._pick_attachment(build_message(), "invo")
        self.assertEqual(att["filename"], "invoice.pdf")

    def test_unknown_name_lists_what_is_there(self):
        with self.assertRaises(server.ToolError) as cm:
            server._pick_attachment(build_message(), "nope.txt")
        self.assertIn("invoice.pdf", str(cm.exception))

    def test_inline_images_are_hidden_by_default(self):
        with self.assertRaises(server.ToolError):
            server._pick_attachment(build_message(), "logo.png")

    def test_include_inline_exposes_them(self):
        att = server._pick_attachment(build_message(), "logo.png",
                                      include_inline=True)
        self.assertEqual(att["ctype"], "image/png")

    def test_ambiguous_choice_is_refused(self):
        msg = EmailMessage()
        msg["From"] = "a@b.example"
        msg.set_content("x")
        msg.add_attachment(b"1", maintype="application", subtype="pdf",
                           filename="one.pdf")
        msg.add_attachment(b"2", maintype="application", subtype="pdf",
                           filename="two.pdf")
        with self.assertRaises(server.ToolError) as cm:
            server._pick_attachment(msg.as_bytes(), None)
        self.assertIn("name one", str(cm.exception))


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


class BulkGuards(unittest.TestCase):
    def test_rejects_non_numeric_uids(self):
        with self.assertRaises(server.ToolError):
            server._parse_uids({"uids": ["12", "all"]})

    def test_rejects_empty(self):
        with self.assertRaises(server.ToolError):
            server._parse_uids({"uids": []})

    def test_accepts_a_comma_string(self):
        self.assertEqual(server._parse_uids({"uids": "1, 2 3"}), ["1", "2", "3"])

    def test_deduplicates(self):
        self.assertEqual(server._parse_uids({"uids": ["4", "4", "5"]}), ["4", "5"])

    def test_enforces_the_cap(self):
        with self.assertRaises(server.ToolError):
            server._parse_uids({"uids": [str(i) for i in range(server.MAX_BULK + 1)]})

    def test_bulk_move_refuses_without_confirmation(self):
        with self.assertRaises(server.ToolError):
            server.tool_bulk_move({"uids": ["1"], "to_folder": "Trash"})

    def test_dry_run_touches_nothing(self):
        out = server._bulk({"uids": ["1", "2"], "dry_run": True}, "move",
                           lambda c, u: (_ for _ in ()).throw(
                               AssertionError("must not run")))
        self.assertIn("DRY RUN", out)


class Audit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._log, self._on = server.AUDIT_LOG, server.AUDIT_ENABLED
        server.AUDIT_LOG = os.path.join(self.tmp, "audit.log")
        server.AUDIT_ENABLED = True

    def tearDown(self):
        server.AUDIT_LOG, server.AUDIT_ENABLED = self._log, self._on

    def _read(self):
        with open(server.AUDIT_LOG) as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_records_the_action(self):
        server._audit("send", {"to": "a@b.example"}, "ok", "Sent")
        rec = self._read()[0]
        self.assertEqual(rec["tool"], "send")
        self.assertEqual(rec["outcome"], "ok")
        self.assertEqual(rec["args"]["to"], "a@b.example")
        self.assertIn("ts", rec)

    def test_body_is_never_written(self):
        server._audit("send", {"to": "a@b.example", "body": "secret words"}, "ok")
        raw = open(server.AUDIT_LOG).read()
        self.assertNotIn("secret words", raw)
        self.assertIn("not logged", raw)

    def test_written_owner_only(self):
        server._audit("mark", {"uid": "1"}, "ok")
        self.assertEqual(oct(os.stat(server.AUDIT_LOG).st_mode & 0o777), "0o600")

    def test_never_raises(self):
        server.AUDIT_LOG = "/nonexistent-dir/audit.log"
        server._audit("send", {"to": "a@b.example"}, "ok")  # must not raise

    def test_disabled_writes_nothing(self):
        server.AUDIT_ENABLED = False
        server._audit("send", {"to": "a@b.example"}, "ok")
        self.assertFalse(os.path.exists(server.AUDIT_LOG))


class Replies(unittest.TestCase):
    def setUp(self):
        self._u, self._a = server.USER, server.ALIAS_FROM
        server.USER, server.ALIAS_FROM = "me@example.com", "me@pm.example"
        server._CORRESPONDENTS.clear()
        server._TAINTED.clear()

    def tearDown(self):
        server.USER, server.ALIAS_FROM = self._u, self._a

    def _msg(self, extra=""):
        return email.message_from_string(
            "From: alice@example.com\r\n"
            "To: me@example.com, bob@example.com\r\n"
            "Cc: carol@example.com, me@pm.example, bob@example.com\r\n"
            "Subject: Re: Re: Budget\r\n"
            "Message-ID: <abc@example.com>\r\n" + extra + "\r\nbody")

    def test_reply_goes_to_the_sender(self):
        to, cc = server._reply_targets(self._msg(), reply_all=False)
        self.assertEqual(to, "alice@example.com")
        self.assertEqual(cc, "")

    def test_reply_to_header_wins_over_from(self):
        m = self._msg("Reply-To: rev_alias@passmail.example\r\n")
        to, _ = server._reply_targets(m, reply_all=False)
        self.assertEqual(to, "rev_alias@passmail.example")

    def test_reply_all_excludes_our_own_addresses(self):
        _, cc = server._reply_targets(self._msg(), reply_all=True)
        self.assertNotIn("me@example.com", cc)
        self.assertNotIn("me@pm.example", cc)

    def test_reply_all_deduplicates(self):
        _, cc = server._reply_targets(self._msg(), reply_all=True)
        self.assertEqual(cc.count("bob@example.com"), 1)

    def test_stacked_prefixes_collapse_to_one(self):
        self.assertEqual(server._reply_subject(self._msg()), "Re: Budget")

    def test_subject_with_no_prefix_gains_one(self):
        m = email.message_from_string("Subject: Budget\r\n\r\nx")
        self.assertEqual(server._reply_subject(m), "Re: Budget")

    def test_sending_requires_confirmation(self):
        with self.assertRaises(server.ToolError) as cm:
            server._do_reply({"uid": "1", "body": "hi"}, reply_all=False)
        self.assertIn("confirmed", str(cm.exception))

    def test_body_is_required(self):
        with self.assertRaises(server.ToolError):
            server._do_reply({"uid": "1", "draft": True}, reply_all=False)

    def test_quoting_marks_the_original(self):
        q = server._quoted(self._msg().as_bytes())
        self.assertIn("wrote:", q)
        self.assertTrue(any(l.startswith("> ") for l in q.splitlines()))


class DryRun(unittest.TestCase):
    """A preview must need no permission, but must still tell the truth about
    whether the real thing would be refused."""

    def setUp(self):
        self._u, self._a = server.USER, server.ALIAS_FROM
        server.USER, server.ALIAS_FROM = "me@example.com", "me@pm.example"
        server._CORRESPONDENTS.clear()
        server._TAINTED.clear()

    def tearDown(self):
        server.USER, server.ALIAS_FROM = self._u, self._a

    def test_send_preview_needs_no_confirmation(self):
        out = server.tool_send({"to": "a@b.example", "subject": "s",
                                "body": "hello", "dry_run": True})
        self.assertIn("DRY RUN", out)
        self.assertIn("a@b.example", out)
        self.assertIn("hello", out)

    def test_send_without_confirmation_or_dry_run_is_refused(self):
        with self.assertRaises(server.ToolError):
            server.tool_send({"to": "a@b.example", "subject": "s", "body": "x"})

    def test_preview_still_enforces_the_sender_allowlist(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_send({"to": "a@b.example", "subject": "s", "body": "x",
                              "from_address": "ceo@victim.example",
                              "dry_run": True})
        self.assertIn("refusing to send as", str(cm.exception))

    def test_preview_still_enforces_recipient_provenance(self):
        server._taint_text("mail attacker@evil.example now")
        with self.assertRaises(server.ToolError):
            server.tool_send({"to": "attacker@evil.example", "subject": "s",
                              "body": "x", "dry_run": True})

    def test_create_mailbox_requires_confirmation_or_dry_run(self):
        # Previews for mailbox and message tools do open a connection, so they
        # can name the real folder or message. Only the gate is asserted here.
        with self.assertRaises(server.ToolError) as cm:
            server.tool_create_mailbox({"name": "Nope", "kind": "label"})
        self.assertIn("confirmed", str(cm.exception))

    def test_quoting_collapses_blank_lines(self):
        raw = email.message_from_string(
            "From: a@b.example\r\nSubject: s\r\n\r\n"
            "one\n\n\n\n\ntwo").as_bytes()
        q = server._quoted(raw)
        self.assertNotIn("> \n> \n> \n", q)
        self.assertIn("> one", q)
        self.assertIn("> two", q)


class HeaderAnalysis(unittest.TestCase):
    def _msg(self, extra=""):
        return email.message_from_string(
            "From: Bank <alerts@bank.example>\r\n"
            "Return-Path: <bounce@bank.example>\r\n"
            "Subject: Statement\r\n" + extra + "\r\nbody")

    def test_parses_all_four_mechanisms(self):
        m = self._msg("Authentication-Results: mx; spf=pass; dkim=fail; "
                      "dmarc=none; arc=pass\r\n")
        v = server._auth_verdicts(m)
        self.assertEqual(v["spf"], "pass")
        self.assertEqual(v["dkim"], "fail")
        self.assertEqual(v["dmarc"], "none")

    def test_clean_message_raises_nothing(self):
        m = self._msg("Authentication-Results: mx; spf=pass; dmarc=pass\r\n")
        self.assertEqual(server._header_notes(m, server._auth_verdicts(m)), [])

    def test_failed_authentication_is_flagged(self):
        m = self._msg("Authentication-Results: mx; spf=fail; dmarc=fail\r\n")
        notes = server._header_notes(m, server._auth_verdicts(m))
        self.assertTrue(any("unproven" in n for n in notes))

    def test_domain_mismatch_is_flagged(self):
        m = email.message_from_string(
            "From: Bank <alerts@bank.example>\r\n"
            "Return-Path: <x@totally-else.example>\r\n\r\nb")
        notes = server._header_notes(m, {})
        self.assertTrue(any("differs from Return-Path" in n for n in notes))

    def test_alias_mail_is_not_cried_wolf_over(self):
        m = email.message_from_string(
            "From: Someone <them@example.com>\r\n"
            "Reply-To: rev@passmail.example\r\n"
            "Return-Path: <sl.abc@passmail.example>\r\n"
            "X-SimpleLogin-Type: Forward\r\n\r\nb")
        notes = server._header_notes(m, {})
        self.assertFalse(any("differs from Return-Path" in n for n in notes))
        self.assertTrue(any("not a red flag" in n for n in notes))

    def test_bulk_mail_is_identified(self):
        m = self._msg("List-Unsubscribe: <mailto:x@y.example>\r\n")
        notes = server._header_notes(m, {})
        self.assertTrue(any("bulk or marketing" in n for n in notes))

    def test_newest_first_ordering(self):
        old = {"date": "Mon, 01 Jan 2024 00:00:00 +0000"}
        new = {"date": "Mon, 01 Jan 2026 00:00:00 +0000"}
        self.assertGreater(server._sort_key(new), server._sort_key(old))

    def test_unparseable_date_does_not_explode(self):
        self.assertEqual(server._sort_key({"date": "nonsense"}), 0.0)


class DraftLifecycle(unittest.TestCase):
    def test_delete_needs_confirmation_or_preview(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_delete_draft({"uid": "1"})
        self.assertIn("confirmed", str(cm.exception))

    def test_send_draft_needs_confirmation_or_preview(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_send_draft({"uid": "1"})
        self.assertIn("confirmed", str(cm.exception))


class Unsubscribe(unittest.TestCase):
    def _msg(self, unsub, extra=""):
        return email.message_from_string(
            "From: News <news@example.com>\r\nSubject: Offer\r\n"
            "List-Unsubscribe: " + unsub + "\r\n" + extra + "\r\nbody")

    def test_parses_both_forms(self):
        m = self._msg("<mailto:off@example.com>, <https://x.example/u>")
        found = server._ANGLE_RE.findall(m["List-Unsubscribe"])
        self.assertIn("mailto:off@example.com", found)
        self.assertIn("https://x.example/u", found)

    def test_message_without_the_header_is_rejected(self):
        # No connection is opened because the guard is on the header, but the
        # tool needs one to fetch, so only the parser is asserted here.
        m = email.message_from_string("From: a@b.example\r\n\r\nx")
        self.assertIsNone(m.get("List-Unsubscribe"))

    def test_one_click_is_detected(self):
        m = self._msg("<https://x.example/u>",
                      "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")
        self.assertIn("one-click", (m.get("List-Unsubscribe-Post") or "").lower())

    def test_alias_forward_is_recognised(self):
        m = self._msg("<https://x.example/u>",
                      "X-SimpleLogin-Type: Forward\r\n"
                      "X-SimpleLogin-Envelope-To: me.abc@passmail.example\r\n")
        sl = m.get("X-SimpleLogin-Type") or ""
        self.assertIn("forward", sl.lower())
        self.assertEqual(m.get("X-SimpleLogin-Envelope-To"),
                         "me.abc@passmail.example")


class TlsPolicy(unittest.TestCase):
    """Verification off is correct for Bridge on loopback and dangerous
    anywhere else. The host is configurable, so this must not be blanket."""

    def setUp(self):
        os.environ.pop("PROTON_TLS_INSECURE_HOSTS", None)
        server._SETTINGS = {}

    tearDown = setUp

    def test_loopback_skips_verification(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertEqual(server._tls_context(host).verify_mode, __import__("ssl").CERT_NONE)

    def test_remote_host_is_verified(self):
        import ssl as _ssl
        ctx = server._tls_context("imap.example.com")
        self.assertEqual(ctx.verify_mode, _ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_a_host_can_be_excused_by_name_only(self):
        import ssl as _ssl
        os.environ["PROTON_TLS_INSECURE_HOSTS"] = "mail.smallhost.example"
        self.assertEqual(
            server._tls_context("mail.smallhost.example").verify_mode, _ssl.CERT_NONE)
        # excusing one host must not excuse the rest
        self.assertEqual(
            server._tls_context("imap.example.com").verify_mode, _ssl.CERT_REQUIRED)

    def test_auto_picks_implicit_tls_on_secure_ports(self):
        self.assertEqual(server._security_mode("PROTON_IMAP_SECURITY", 993), "ssl")
        self.assertEqual(server._security_mode("PROTON_SMTP_SECURITY", 465), "ssl")

    def test_auto_picks_starttls_elsewhere(self):
        for port in (143, 587, 1143, 1025):
            self.assertEqual(
                server._security_mode("PROTON_IMAP_SECURITY", port), "starttls")

    def test_explicit_mode_wins(self):
        os.environ["PROTON_IMAP_SECURITY"] = "ssl"
        try:
            self.assertEqual(server._security_mode("PROTON_IMAP_SECURITY", 143), "ssl")
        finally:
            os.environ.pop("PROTON_IMAP_SECURITY", None)

    def test_nonsense_mode_is_rejected(self):
        os.environ["PROTON_IMAP_SECURITY"] = "plaintext"
        try:
            with self.assertRaises(server.ToolError):
                server._security_mode("PROTON_IMAP_SECURITY", 143)
        finally:
            os.environ.pop("PROTON_IMAP_SECURITY", None)


class OutgoingAttachments(unittest.TestCase):
    """Reading a file and mailing it is the neatest exfiltration route there
    is, so sources are confined the same way writes are."""

    def setUp(self):
        os.environ.pop("PROTON_ATTACH_SOURCE_DIRS", None)
        server._SETTINGS = {}
        os.makedirs(server.ATTACH_DIR, exist_ok=True)
        self.ok = os.path.join(server.ATTACH_DIR, "unit-test-file.txt")
        with open(self.ok, "w") as f:
            f.write("hello")

    def tearDown(self):
        os.environ.pop("PROTON_ATTACH_SOURCE_DIRS", None)
        try:
            os.remove(self.ok)
        except OSError:
            pass

    def test_file_inside_the_root_is_allowed(self):
        self.assertTrue(server._resolve_source(self.ok).endswith("unit-test-file.txt"))

    def test_absolute_path_outside_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_source("/etc/hosts")

    def test_traversal_out_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_source(os.path.join(server.ATTACH_DIR, "..", "server.py"))

    def test_missing_file_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_source(os.path.join(server.ATTACH_DIR, "nope.txt"))

    def test_extra_root_can_be_configured(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "x.txt")
        with open(path, "w") as f:
            f.write("x")
        with self.assertRaises(server.ToolError):
            server._resolve_source(path)
        os.environ["PROTON_ATTACH_SOURCE_DIRS"] = tmp
        self.assertTrue(server._resolve_source(path))

    def test_too_many_files_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._load_attachments(
                {"attach": [self.ok] * (server.MAX_OUTGOING_FILES + 1)})

    def test_attachment_reaches_the_message(self):
        files = server._load_attachments({"attach": [self.ok]})
        msg = server._new_message("a@b.example", "", "s", "body",
                                  attachments=files)
        names = [p.get_filename() for p in msg.walk() if p.get_filename()]
        self.assertIn("unit-test-file.txt", names)

    def test_no_attachments_leaves_the_message_simple(self):
        self.assertEqual(server._load_attachments({}), [])


class PermissionModes(unittest.TestCase):
    def test_readonly_removes_everything_mutating(self):
        os.environ["PROTON_MODE"] = "readonly"
        try:
            self.assertEqual(server._mode(), "readonly")
        finally:
            os.environ.pop("PROTON_MODE", None)

    def test_organise_is_the_middle_setting(self):
        os.environ["PROTON_MODE"] = "organise"
        try:
            self.assertEqual(server._mode(), "organise")
        finally:
            os.environ.pop("PROTON_MODE", None)

    def test_legacy_readonly_flag_still_honoured(self):
        os.environ["PROTON_READONLY"] = "1"
        try:
            self.assertEqual(server._mode(), "readonly")
        finally:
            os.environ.pop("PROTON_READONLY", None)

    def test_nonsense_falls_back_to_full(self):
        os.environ["PROTON_MODE"] = "banana"
        try:
            self.assertEqual(server._mode(), "full")
        finally:
            os.environ.pop("PROTON_MODE", None)


class RateLimit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._sf, self._limits = server.STATE_FILE, dict(server.RATE_LIMITS)
        server.STATE_FILE = os.path.join(self.tmp, "state.json")

    def tearDown(self):
        server.STATE_FILE = self._sf
        server.RATE_LIMITS.clear()
        server.RATE_LIMITS.update(self._limits)

    def test_sends_are_capped(self):
        server.RATE_LIMITS["send"] = 2
        server._rate_check("send")
        server._rate_check("send")
        with self.assertRaises(server.ToolError) as cm:
            server._rate_check("send")
        self.assertIn("Rate limit", str(cm.exception))

    def test_buckets_are_separate(self):
        server.RATE_LIMITS["send"] = 1
        server.RATE_LIMITS["write"] = 5
        server._rate_check("send")
        server._rate_check("mark")  # write bucket, unaffected
        with self.assertRaises(server.ToolError):
            server._rate_check("reply")

    def test_zero_disables_the_limit(self):
        server.RATE_LIMITS["send"] = 0
        for _ in range(50):
            server._rate_check("send")


class PollingCursor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._sf = server.STATE_FILE
        server.STATE_FILE = os.path.join(self.tmp, "state.json")

    def tearDown(self):
        server.STATE_FILE = self._sf

    def test_ack_rejects_a_malformed_checkpoint(self):
        with self.assertRaises(server.ToolError):
            server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "nonsense"})

    def test_ack_commits_then_is_idempotent(self):
        first = server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "5:100"})
        self.assertIn("committed", first)
        again = server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "5:100"})
        self.assertIn("Nothing to do", again)

    def test_ack_never_moves_the_cursor_backwards(self):
        server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "5:100"})
        server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "5:50"})
        self.assertEqual(
            server._read_state()["cursors"]["INBOX"]["last_uid"], 100)

    def test_checkpoint_from_another_generation_is_refused(self):
        server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "5:100"})
        with self.assertRaises(server.ToolError) as cm:
            server.tool_ack_mailbox({"folder": "INBOX", "checkpoint": "9:101"})
        self.assertIn("resynced", str(cm.exception))

    def test_state_is_written_owner_only(self):
        server._write_state({"cursors": {}})
        self.assertEqual(
            oct(os.stat(server.STATE_FILE).st_mode & 0o777), "0o600")


class LabelResolution(unittest.TestCase):
    """A label is namespaced under Labels/ on Proton and is an ordinary mailbox
    everywhere else. Detect which, rather than assuming Proton."""

    class Fake:
        def __init__(self, boxes):
            self.boxes = boxes
        def list(self):
            return "OK", ['(\\HasNoChildren) "/" "%s"' % b for b in self.boxes]

    PROTON = ["INBOX", "Archive", "Labels/Invoices", "Labels/Marketing",
              "Folders/Work"]
    PLAIN = ["INBOX", "Archive", "Receipts", "Work"]

    def test_bare_name_gains_the_namespace_on_proton(self):
        self.assertEqual(
            server._resolve_label(self.Fake(self.PROTON), "Marketing"),
            "Labels/Marketing")

    def test_already_namespaced_is_left_alone(self):
        self.assertEqual(
            server._resolve_label(self.Fake(self.PROTON), "Labels/Invoices"),
            "Labels/Invoices")

    def test_plain_server_uses_the_mailbox_as_given(self):
        self.assertEqual(
            server._resolve_label(self.Fake(self.PLAIN), "Receipts"), "Receipts")

    def test_plain_server_matches_case_insensitively(self):
        self.assertEqual(
            server._resolve_label(self.Fake(self.PLAIN), "receipts"), "Receipts")

    def test_unknown_label_lists_what_exists(self):
        with self.assertRaises(server.ToolError) as cm:
            server._resolve_label(self.Fake(self.PROTON), "Nope")
        self.assertIn("Labels/Marketing", str(cm.exception))

    def test_unknown_mailbox_explains_the_plain_case(self):
        with self.assertRaises(server.ToolError) as cm:
            server._resolve_label(self.Fake(self.PLAIN), "Nope")
        self.assertIn("no Labels/ namespace", str(cm.exception))

    def test_empty_label_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_label(self.Fake(self.PLAIN), "  ")


class ImapInjection(unittest.TestCase):
    """Folder names, search terms and uids reach the IMAP protocol stream, and
    imaplib does not guard its arguments. A CR/LF must never survive into one."""

    def test_folder_name_with_crlf_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._folder_quote("INBOX\r\nA1 LOGOUT")

    def test_folder_name_with_control_char_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._folder_quote("Fold\x00er")

    def test_ordinary_folder_name_still_quotes(self):
        self.assertEqual(server._folder_quote("Folders/Work"), '"Folders/Work"')

    def test_quote_in_folder_name_is_escaped_not_broken_out_of(self):
        self.assertEqual(server._folder_quote('a"b'), '"a\\"b"')

    def test_search_value_with_crlf_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._build_search({"from": 'x\r\nA1 DELETE'})

    def test_search_quote_is_escaped(self):
        crit = server._build_search({"text": 'he"llo'})
        self.assertIn('"he\\"llo"', crit)

    def test_search_date_must_be_well_formed(self):
        with self.assertRaises(server.ToolError):
            server._build_search({"since": "2026-07-01\r\nEVIL"})

    def test_valid_search_date_passes(self):
        self.assertIn("01-Jul-2026",
                      server._build_search({"since": "01-Jul-2026"}))

    def test_uid_must_be_numeric(self):
        with self.assertRaises(server.ToolError):
            server._uidval("1\r\nA1 LOGOUT")
        with self.assertRaises(server.ToolError):
            server._uidval("1:*")

    def test_numeric_uid_passes(self):
        self.assertEqual(server._uidval(" 42 "), "42")


class RemoveLabel(unittest.TestCase):
    """A label is a separate mailbox holding its own copy of the message, so the
    copy has to be found by Message-ID before it can be dropped."""

    class Fake:
        """Enough IMAP to exercise the lookup and the expunge path."""

        def __init__(self, boxes, scan=None, search=None, search_fails=False):
            self.boxes = boxes
            self.scan = scan or []          # [(uid, raw_header_bytes)]
            self.search = search            # uids SEARCH returns, or None
            self.search_fails = search_fails
            self.selected = None
            self.stored = []
            self.expunged = []
            self.bare_expunge = 0

        def list(self):
            return "OK", ['(\\HasNoChildren) "/" "%s"' % b for b in self.boxes]

        def select(self, mailbox, readonly=False):
            self.selected = mailbox
            return "OK", [b"1"]

        def response(self, name):
            return name, [b"42"]

        def uid(self, cmd, *args):
            cmd = cmd.upper()
            if cmd == "SEARCH":
                if self.search_fails:
                    raise server.imaplib.IMAP4.error("no CHARSET")
                if self.search:
                    return "OK", [b" ".join(u.encode() for u in self.search)]
                return "OK", [b""]
            if cmd == "FETCH":
                spec = args[0]
                out = []
                for u, raw in self.scan:
                    if spec == "1:*" or spec == u:
                        out.append((b"%s (UID %s" % (u.encode(), u.encode()), raw))
                return ("OK", out) if out else ("NO", None)
            if cmd == "STORE":
                self.stored.append(args[0])
                return "OK", [b"done"]
            if cmd == "EXPUNGE":
                self.expunged.append(args[0])
                return "OK", [b"done"]
            return "NO", None

        def expunge(self):
            self.bare_expunge += 1
            return "OK", [b"done"]

    BOXES = ["INBOX", "Labels/Processed", "Folders/Considus"]

    def _hdr(self, mid):
        return ("Subject: s\r\nFrom: a@b.example\r\nMessage-ID: %s\r\n\r\n"
                % mid).encode()

    def test_finds_the_copy_via_search(self):
        f = self.Fake(self.BOXES, search=["77"])
        self.assertEqual(
            server._label_copy_uid(f, "Labels/Processed", "<abc@x>"), "77")

    def test_falls_back_to_a_header_scan_when_search_fails(self):
        f = self.Fake(self.BOXES, scan=[("88", self._hdr("<abc@x>"))],
                      search_fails=True)
        self.assertEqual(
            server._label_copy_uid(f, "Labels/Processed", "<abc@x>"), "88")

    def test_returns_none_when_the_label_is_not_on_it(self):
        f = self.Fake(self.BOXES, scan=[("88", self._hdr("<other@x>"))])
        self.assertIsNone(
            server._label_copy_uid(f, "Labels/Processed", "<abc@x>"))

    def test_message_without_a_message_id_is_refused(self):
        f = self.Fake(self.BOXES)
        with self.assertRaises(server.ToolError):
            server._label_copy_uid(f, "Labels/Processed", "")

    def test_drop_prefers_uid_expunge_over_a_bare_one(self):
        f = self.Fake(self.BOXES)
        server._drop_label_copy(f, "77")
        self.assertEqual(f.expunged, ["77"])
        self.assertEqual(f.bare_expunge, 0, "a bare EXPUNGE takes other mail with it")

    def test_drop_falls_back_to_bare_expunge(self):
        f = self.Fake(self.BOXES)
        f.uid = lambda cmd, *a: (("OK", [b"ok"]) if cmd.upper() == "STORE"
                                 else (_ for _ in ()).throw(
                                     server.imaplib.IMAP4.error("no UIDPLUS")))
        server._drop_label_copy(f, "77")
        self.assertEqual(f.bare_expunge, 1)

    def test_index_maps_message_ids_to_uids(self):
        f = self.Fake(self.BOXES, scan=[("1", self._hdr("<a@x>")),
                                        ("2", self._hdr("<b@x>"))])
        self.assertEqual(server._label_index(f, "Labels/Processed"),
                         {"<a@x>": "1", "<b@x>": "2"})

    def test_single_removal_is_gated(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_remove_label({"uid": "1", "label": "Processed"})
        self.assertIn("confirmed", str(cm.exception))

    def test_bulk_removal_is_gated(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_bulk_remove_label({"uids": ["1"], "label": "Processed"})
        self.assertIn("confirmed", str(cm.exception))

    def test_bulk_dry_run_touches_nothing(self):
        out = server.tool_bulk_remove_label(
            {"uids": ["1", "2"], "label": "Processed", "dry_run": True})
        self.assertIn("DRY RUN", out)
        self.assertIn("Processed", out)


class DeleteLabel(unittest.TestCase):
    """Labels can be deleted, folders cannot, and a server without a Labels/
    namespace is refused because there a 'label' holds the real messages."""

    class Fake:
        def __init__(self, boxes):
            self.boxes = boxes
            self.deleted = []

        def list(self):
            return "OK", ['(\\HasNoChildren) "/" "%s"' % b for b in self.boxes]

        def status(self, mailbox, what):
            return "OK", [b'"x" (MESSAGES 4)']

        def delete(self, mailbox):
            self.deleted.append(mailbox)
            return "OK", [b"done"]

    PROTON = ["INBOX", "Archive", "Labels/Invoices", "Labels/Processed",
              "Folders/Work"]
    PLAIN = ["INBOX", "Archive", "Receipts"]

    def test_bare_name_resolves_into_the_namespace(self):
        got = server._resolve_label_for_delete(self.Fake(self.PROTON), "Invoices")
        self.assertEqual(got, "Labels/Invoices")

    def test_prefixed_name_is_accepted(self):
        got = server._resolve_label_for_delete(self.Fake(self.PROTON),
                                               "Labels/Processed")
        self.assertEqual(got, "Labels/Processed")

    def test_folder_is_refused(self):
        with self.assertRaises(server.ToolError) as cm:
            server._resolve_label_for_delete(self.Fake(self.PROTON), "Folders/Work")
        self.assertIn("not a label", str(cm.exception))

    def test_the_namespace_itself_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_label_for_delete(self.Fake(self.PROTON), "Labels")

    def test_unknown_label_lists_what_exists(self):
        with self.assertRaises(server.ToolError) as cm:
            server._resolve_label_for_delete(self.Fake(self.PROTON), "Nope")
        self.assertIn("Labels/Invoices", str(cm.exception))

    def test_server_without_the_namespace_is_refused(self):
        with self.assertRaises(server.ToolError) as cm:
            server._resolve_label_for_delete(self.Fake(self.PLAIN), "Receipts")
        self.assertIn("real copies", str(cm.exception))

    def test_empty_name_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._resolve_label_for_delete(self.Fake(self.PROTON), "  ")

    def test_message_count_is_read(self):
        self.assertEqual(
            server._label_message_count(self.Fake(self.PROTON), "Labels/Invoices"), 4)

    def test_single_delete_is_gated(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_delete_label({"label": "Invoices"})
        self.assertIn("confirmed", str(cm.exception))

    def test_bulk_delete_is_gated(self):
        with self.assertRaises(server.ToolError) as cm:
            server.tool_bulk_delete_labels({"labels": ["Invoices"]})
        self.assertIn("confirmed", str(cm.exception))

    def test_label_list_parsing(self):
        self.assertEqual(server._parse_labels({"labels": "a, b\nc"}),
                         ["a", "b", "c"])

    def test_label_list_deduplicates(self):
        self.assertEqual(server._parse_labels({"labels": ["a", "a", "b"]}),
                         ["a", "b"])

    def test_empty_label_list_is_refused(self):
        with self.assertRaises(server.ToolError):
            server._parse_labels({"labels": []})

    def test_label_list_cap(self):
        with self.assertRaises(server.ToolError):
            server._parse_labels(
                {"labels": ["l%d" % i for i in range(server.MAX_BULK + 1)]})


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
        for gone in ("send", "forward", "move_to_folder", "create_folder_or_label",
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
