"""Unit tests for lego.py pure-logic functions."""

import datetime
import pathlib
import sys
import tempfile
import unittest

# Allow running from repo root: python3 -m unittest discover -s tests -v
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import lego  # noqa: E402  (after sys.path manipulation)


# ---------------------------------------------------------------------------
# parse_env_file
# ---------------------------------------------------------------------------


class TestParseEnvFile(unittest.TestCase):
    def _parse(self, content: str) -> dict[str, str]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".env", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = pathlib.Path(f.name)
        try:
            return lego.parse_env_file(path)
        finally:
            path.unlink()

    def test_simple_assignment(self):
        self.assertEqual(self._parse("FOO=bar\n"), {"FOO": "bar"})

    def test_double_quoted_value(self):
        self.assertEqual(self._parse('KEY="hello world"\n'), {"KEY": "hello world"})

    def test_single_quoted_value(self):
        self.assertEqual(self._parse("KEY='hello world'\n"), {"KEY": "hello world"})

    def test_comment_ignored(self):
        result = self._parse("# this is a comment\nFOO=bar\n")
        self.assertEqual(result, {"FOO": "bar"})

    def test_blank_lines_ignored(self):
        result = self._parse("\n\nFOO=bar\n\n")
        self.assertEqual(result, {"FOO": "bar"})

    def test_multiple_keys(self):
        result = self._parse("A=1\nB=2\nC=3\n")
        self.assertEqual(result, {"A": "1", "B": "2", "C": "3"})

    def test_value_with_equals(self):
        # Values may contain = (e.g. base64 secrets)
        result = self._parse("SECRET=abc=def==\n")
        self.assertEqual(result, {"SECRET": "abc=def=="})

    def test_empty_value(self):
        self.assertEqual(self._parse("FOO=\n"), {"FOO": ""})

    def test_empty_quoted_value(self):
        self.assertEqual(self._parse('FOO=""\n'), {"FOO": ""})

    def test_inline_comment_not_stripped(self):
        # The parser does NOT strip inline comments — value includes everything after =
        result = self._parse("FOO=bar # not a comment\n")
        self.assertEqual(result["FOO"], "bar # not a comment")

    def test_domains_format(self):
        result = self._parse('DOMAINS="-d foo.example.com -d bar.example.com"\n')
        self.assertEqual(result["DOMAINS"], "-d foo.example.com -d bar.example.com")


# ---------------------------------------------------------------------------
# mask_sensitive
# ---------------------------------------------------------------------------


class TestMaskSensitive(unittest.TestCase):
    def test_key_suffix_masked(self):
        self.assertEqual(lego.mask_sensitive("CLOUDFLARE_DNS_API_KEY", "secret"), "****")

    def test_kid_masked(self):
        self.assertEqual(lego.mask_sensitive("LEGO_EAB_KID", "mykid"), "****")

    def test_hmac_masked(self):
        self.assertEqual(lego.mask_sensitive("LEGO_EAB_HMAC", "myhmac"), "****")

    def test_token_masked(self):
        self.assertEqual(lego.mask_sensitive("CLOUDFLARE_DNS_API_TOKEN", "tok"), "****")

    def test_secret_masked(self):
        self.assertEqual(lego.mask_sensitive("MY_SECRET", "val"), "****")

    def test_password_masked(self):
        self.assertEqual(lego.mask_sensitive("LEGO_PFX_PASSWORD", "pw"), "****")

    def test_pass_masked(self):
        self.assertEqual(lego.mask_sensitive("DB_PASS", "pw"), "****")

    def test_case_insensitive(self):
        self.assertEqual(lego.mask_sensitive("my_token", "val"), "****")

    def test_email_not_masked(self):
        self.assertEqual(
            lego.mask_sensitive("LEGO_EMAIL", "user@example.com"), "user@example.com"
        )

    def test_server_not_masked(self):
        url = "https://acme.example.com"
        self.assertEqual(lego.mask_sensitive("LEGO_SERVER", url), url)

    def test_dns_not_masked(self):
        self.assertEqual(lego.mask_sensitive("LEGO_DNS", "cloudflare"), "cloudflare")

    def test_eab_flag_not_masked(self):
        # LEGO_EAB itself does not match the pattern (no KEY/KID/HMAC/TOKEN/etc.)
        self.assertEqual(lego.mask_sensitive("LEGO_EAB", "true"), "true")


# ---------------------------------------------------------------------------
# _parse_domains
# ---------------------------------------------------------------------------


class TestParseDomains(unittest.TestCase):
    def test_single_domain(self):
        self.assertEqual(lego._parse_domains("-d foo.example.com"), ["foo.example.com"])

    def test_multiple_domains(self):
        result = lego._parse_domains("-d foo.example.com -d bar.example.com")
        self.assertEqual(result, ["foo.example.com", "bar.example.com"])

    def test_long_flag(self):
        result = lego._parse_domains("--domains foo.example.com --domains bar.example.com")
        self.assertEqual(result, ["foo.example.com", "bar.example.com"])

    def test_empty_string(self):
        self.assertEqual(lego._parse_domains(""), [])

    def test_no_flag_prefix(self):
        # A bare domain without -d is not recognised
        self.assertEqual(lego._parse_domains("foo.example.com"), [])

    def test_mixed_flags(self):
        result = lego._parse_domains("-d foo.example.com --domains bar.example.com")
        self.assertEqual(result, ["foo.example.com", "bar.example.com"])


# ---------------------------------------------------------------------------
# _parse_lego_expiry
# ---------------------------------------------------------------------------


class TestParseLegoCertExpiry(unittest.TestCase):
    def test_standard_format(self):
        dt = lego._parse_lego_expiry("2026-06-06 23:59:59 +0000 UTC")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 6)
        self.assertEqual(dt.day, 6)
        self.assertEqual(dt.hour, 23)
        self.assertEqual(dt.minute, 59)
        self.assertEqual(dt.second, 59)
        self.assertIsNotNone(dt.tzinfo)

    def test_utc_suffix_stripped(self):
        # Should not raise even with trailing 'UTC'
        dt = lego._parse_lego_expiry("2025-01-15 12:00:00 +0000 UTC")
        self.assertEqual(dt.year, 2025)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            lego._parse_lego_expiry("not a date")


# ---------------------------------------------------------------------------
# _parse_lego_list
# ---------------------------------------------------------------------------

_LEGO_LIST_SINGLE = """\
Found the following certs:
  Certificate Name: foo.example.com
    Domains: foo.example.com
    Expiry Date: 2026-06-06 23:59:59 +0000 UTC
    Certificate Path: /var/lib/acme/certificates/foo.example.com.crt
    Private Key Path: /var/lib/acme/certificates/foo.example.com.key
"""

_LEGO_LIST_MULTI = """\
Found the following certs:
  Certificate Name: foo.example.com
    Domains: foo.example.com, bar.example.com
    Expiry Date: 2026-06-06 23:59:59 +0000 UTC
    Certificate Path: /var/lib/acme/certificates/foo.example.com.crt
    Private Key Path: /var/lib/acme/certificates/foo.example.com.key
  Certificate Name: baz.example.com
    Domains: baz.example.com
    Expiry Date: 2026-09-01 00:00:00 +0000 UTC
    Certificate Path: /var/lib/acme/certificates/baz.example.com.crt
    Private Key Path: /var/lib/acme/certificates/baz.example.com.key
"""


class TestParseLegoCertList(unittest.TestCase):
    def test_single_cert_parsed(self):
        result = lego._parse_lego_list(_LEGO_LIST_SINGLE)
        self.assertIn("foo.example.com", result)

    def test_single_cert_domains(self):
        result = lego._parse_lego_list(_LEGO_LIST_SINGLE)
        self.assertEqual(result["foo.example.com"].domains, ["foo.example.com"])

    def test_single_cert_expiry_year(self):
        result = lego._parse_lego_list(_LEGO_LIST_SINGLE)
        self.assertEqual(result["foo.example.com"].expiry.year, 2026)

    def test_single_cert_path(self):
        result = lego._parse_lego_list(_LEGO_LIST_SINGLE)
        expected = pathlib.Path(
            "/var/lib/acme/certificates/foo.example.com.crt"
        )
        self.assertEqual(result["foo.example.com"].cert_path, expected)

    def test_multiple_certs(self):
        result = lego._parse_lego_list(_LEGO_LIST_MULTI)
        self.assertIn("foo.example.com", result)
        self.assertIn("baz.example.com", result)

    def test_multiple_domains_parsed(self):
        result = lego._parse_lego_list(_LEGO_LIST_MULTI)
        self.assertEqual(
            result["foo.example.com"].domains,
            ["foo.example.com", "bar.example.com"],
        )

    def test_empty_output(self):
        result = lego._parse_lego_list("")
        self.assertEqual(result, {})

    def test_no_certs_line(self):
        result = lego._parse_lego_list("No certificates found.\n")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# _cert_state
# ---------------------------------------------------------------------------


class TestCertState(unittest.TestCase):
    def _expiry(self, days_from_now: int) -> datetime.datetime:
        return datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days_from_now)

    def test_valid(self):
        self.assertEqual(lego._cert_state(self._expiry(60)), lego.CertState.VALID)

    def test_expiring_soon(self):
        # 29 days: >= EXPIRY_CRIT_DAYS (15) and < EXPIRY_WARN_DAYS (30)
        self.assertEqual(
            lego._cert_state(self._expiry(29)), lego.CertState.EXPIRING_SOON
        )

    def test_expiring_critical(self):
        # 7 days: < EXPIRY_CRIT_DAYS (15)
        self.assertEqual(
            lego._cert_state(self._expiry(7)), lego.CertState.EXPIRING_CRITICAL
        )

    def test_expired(self):
        self.assertEqual(lego._cert_state(self._expiry(-1)), lego.CertState.EXPIRED)

    def test_boundary_warn(self):
        # timedelta.days is a floor: adding exactly EXPIRY_WARN_DAYS seconds later
        # yields days=EXPIRY_WARN_DAYS-1, which is < EXPIRY_WARN_DAYS → EXPIRING_SOON.
        self.assertEqual(
            lego._cert_state(self._expiry(lego.EXPIRY_WARN_DAYS)),
            lego.CertState.EXPIRING_SOON,
        )

    def test_boundary_crit(self):
        # Same floor effect: adding exactly EXPIRY_CRIT_DAYS yields days=EXPIRY_CRIT_DAYS-1
        # which is < EXPIRY_CRIT_DAYS → EXPIRING_CRITICAL.
        self.assertEqual(
            lego._cert_state(self._expiry(lego.EXPIRY_CRIT_DAYS)),
            lego.CertState.EXPIRING_CRITICAL,
        )


# ---------------------------------------------------------------------------
# _config_update
# ---------------------------------------------------------------------------


class TestConfigUpdate(unittest.TestCase):
    def _roundtrip(self, initial: str, key: str, value: str) -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8"
        ) as f:
            f.write(initial)
            path = pathlib.Path(f.name)
        try:
            lego._config_update(path, key, value)
            return path.read_text(encoding="utf-8")
        finally:
            path.unlink()

    def test_update_existing_key(self):
        result = self._roundtrip('FOO="old"\n', "FOO", "new")
        self.assertIn('FOO="new"', result)
        self.assertNotIn("old", result)

    def test_append_new_key(self):
        result = self._roundtrip('FOO="bar"\n', "BAZ", "qux")
        self.assertIn('FOO="bar"', result)
        self.assertIn('BAZ="qux"', result)

    def test_commented_line_not_updated(self):
        result = self._roundtrip('#FOO="old"\n', "FOO", "new")
        self.assertIn('#FOO="old"', result)
        self.assertIn('FOO="new"', result)

    def test_preserves_other_lines(self):
        result = self._roundtrip("# comment\nFOO=old\nBAR=keep\n", "FOO", "new")
        self.assertIn("# comment", result)
        self.assertIn("BAR=keep", result)

    def test_empty_file_appends(self):
        result = self._roundtrip("", "KEY", "val")
        self.assertIn('KEY="val"', result)

    def test_value_with_special_chars(self):
        result = self._roundtrip("", "URL", "https://acme.example.com/v2/DV90")
        self.assertIn('URL="https://acme.example.com/v2/DV90"', result)

    def test_value_with_embedded_quote(self):
        result = self._roundtrip("", "KEY", 'say "hello"')
        self.assertIn(r'KEY="say \"hello\""', result)

    def test_missing_file_creates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "new.conf"
            lego._config_update(path, "KEY", "val")
            self.assertIn('KEY="val"', path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# _quote_value
# ---------------------------------------------------------------------------


class TestQuoteValue(unittest.TestCase):
    def test_simple_value(self):
        self.assertEqual(lego._quote_value("hello"), '"hello"')

    def test_empty_string(self):
        self.assertEqual(lego._quote_value(""), '""')

    def test_embedded_double_quote(self):
        self.assertEqual(lego._quote_value('say "hi"'), r'"say \"hi\""')

    def test_url_value(self):
        url = "https://acme.example.com/v2/DV90"
        self.assertEqual(lego._quote_value(url), f'"{url}"')

    def test_spaces_preserved(self):
        self.assertEqual(lego._quote_value("-d foo -d bar"), '"-d foo -d bar"')


# ---------------------------------------------------------------------------
# _build_lego_run_cmd
# ---------------------------------------------------------------------------


class TestBuildLegoRunCmdV4(unittest.TestCase):
    """v4: global flags before the subcommand; 'run' vs 'renew' as distinct actions."""

    _LEGO = pathlib.Path("/usr/bin/lego")
    _VER = (4, 9, 1)
    _BASE_CONF = {
        "LEGO_EMAIL": "admin@example.com",
        "LEGO_DNS": "cloudflare",
    }
    _DOMAINS = ["foo.example.com", "bar.example.com"]

    def _cmd(
        self,
        conf: dict | None = None,
        domains: list | None = None,
        hook: str = "",
        action: str = "issue",
    ) -> list[str]:
        return lego._build_lego_run_cmd(
            self._LEGO,
            conf if conf is not None else self._BASE_CONF,
            domains if domains is not None else self._DOMAINS,
            hook,
            self._VER,
            action,
        )

    def test_accept_tos_present(self):
        self.assertIn("--accept-tos", self._cmd())

    def test_path_present(self):
        cmd = self._cmd()
        self.assertIn("--path", cmd)
        idx = cmd.index("--path")
        self.assertEqual(cmd[idx + 1], str(lego.ACME_WORK_DIR))

    def test_email_present(self):
        cmd = self._cmd()
        self.assertIn("--email", cmd)
        idx = cmd.index("--email")
        self.assertEqual(cmd[idx + 1], "admin@example.com")

    def test_domains_present(self):
        cmd = self._cmd()
        pairs = [(cmd[i], cmd[i + 1]) for i in range(len(cmd) - 1) if cmd[i] == "-d"]
        self.assertEqual([d for _, d in pairs], self._DOMAINS)

    def test_dns_present(self):
        cmd = self._cmd()
        self.assertIn("--dns", cmd)
        idx = cmd.index("--dns")
        self.assertEqual(cmd[idx + 1], "cloudflare")

    def test_issue_appends_run(self):
        cmd = self._cmd(action="issue")
        self.assertIn("run", cmd)
        self.assertNotIn("renew", cmd)

    def test_renew_appends_renew(self):
        cmd = self._cmd(action="renew")
        self.assertIn("renew", cmd)
        self.assertNotIn("run", cmd)

    def test_subcommand_after_dns(self):
        cmd = self._cmd(action="issue")
        self.assertGreater(cmd.index("run"), cmd.index("--dns"))

    def test_accept_tos_before_subcommand(self):
        # v4: global flags come before the trailing action subcommand.
        cmd = self._cmd(action="issue")
        self.assertLess(cmd.index("--accept-tos"), cmd.index("run"))

    def test_server_absent_when_not_set(self):
        self.assertNotIn("--server", self._cmd())

    def test_server_present_when_set(self):
        conf = {**self._BASE_CONF, "LEGO_SERVER": "https://acme.example.com"}
        cmd = self._cmd(conf=conf)
        self.assertIn("--server", cmd)
        idx = cmd.index("--server")
        self.assertEqual(cmd[idx + 1], "https://acme.example.com")

    def test_eab_flags_added_when_enabled(self):
        conf = {
            **self._BASE_CONF,
            "LEGO_EAB": "true",
            "LEGO_EAB_KID": "mykid",
            "LEGO_EAB_HMAC": "myhmac",
        }
        cmd = self._cmd(conf=conf)
        self.assertIn("--eab", cmd)
        self.assertIn("--kid", cmd)
        self.assertIn("--hmac", cmd)
        self.assertEqual(cmd[cmd.index("--kid") + 1], "mykid")
        self.assertEqual(cmd[cmd.index("--hmac") + 1], "myhmac")

    def test_eab_flags_absent_when_disabled(self):
        cmd = self._cmd()
        self.assertNotIn("--eab", cmd)
        self.assertNotIn("--kid", cmd)
        self.assertNotIn("--hmac", cmd)

    def test_pfx_flags_added_when_enabled(self):
        conf = {
            **self._BASE_CONF,
            "LEGO_PFX": "true",
            "LEGO_PFX_PASSWORD": "secret",
        }
        cmd = self._cmd(conf=conf)
        self.assertIn("--pfx", cmd)
        self.assertIn("--pfx.password", cmd)
        self.assertEqual(cmd[cmd.index("--pfx.password") + 1], "secret")

    def test_pfx_flags_absent_when_disabled(self):
        self.assertNotIn("--pfx", self._cmd())

    def test_dns_resolvers_present(self):
        conf = {**self._BASE_CONF, "LEGO_DNS_RESOLVERS": "1.1.1.1:53,8.8.8.8:53"}
        cmd = self._cmd(conf=conf)
        resolvers = [
            cmd[i + 1] for i in range(len(cmd) - 1) if cmd[i] == "--dns.resolvers"
        ]
        self.assertEqual(resolvers, ["1.1.1.1:53", "8.8.8.8:53"])

    def test_hook_added_when_present(self):
        cmd = self._cmd(hook="systemctl restart nginx")
        self.assertIn("--run-hook", cmd)
        idx = cmd.index("--run-hook")
        self.assertEqual(cmd[idx + 1], "systemctl restart nginx")

    def test_hook_absent_when_empty(self):
        self.assertNotIn("--run-hook", self._cmd(hook=""))

    def test_hook_after_subcommand(self):
        cmd = self._cmd(hook="systemctl restart nginx", action="issue")
        self.assertGreater(cmd.index("--run-hook"), cmd.index("run"))

    def test_renew_hook_uses_run_hook_flag(self):
        # v4's 'renew' subcommand uses the same --run-hook flag name as 'run'.
        cmd = self._cmd(hook="systemctl restart nginx", action="renew")
        self.assertIn("--run-hook", cmd)
        self.assertGreater(cmd.index("--run-hook"), cmd.index("renew"))


class TestBuildLegoRunCmdV5(unittest.TestCase):
    """v5: flags after the subcommand; 'renew' no longer exists — always 'run'."""

    _LEGO = pathlib.Path("/usr/bin/lego")
    _VER = (5, 4, 0)
    _BASE_CONF = {
        "LEGO_EMAIL": "admin@example.com",
        "LEGO_DNS": "cloudflare",
    }
    _DOMAINS = ["foo.example.com"]

    def _cmd(self, hook: str = "", action: str = "issue") -> list[str]:
        return lego._build_lego_run_cmd(
            self._LEGO, self._BASE_CONF, self._DOMAINS, hook, self._VER, action
        )

    def test_run_is_second_token_for_issue(self):
        cmd = self._cmd(action="issue")
        self.assertEqual(cmd[1], "run")

    def test_run_is_second_token_for_renew_too(self):
        # v5 has no separate 'renew' command — renewal also uses 'run'.
        cmd = self._cmd(action="renew")
        self.assertEqual(cmd[1], "run")
        self.assertNotIn("renew", cmd)

    def test_accept_tos_after_subcommand(self):
        cmd = self._cmd()
        self.assertGreater(cmd.index("--accept-tos"), cmd.index("run"))

    def test_eab_uses_dotted_flags(self):
        conf = {
            **self._BASE_CONF,
            "LEGO_EAB": "true",
            "LEGO_EAB_KID": "mykid",
            "LEGO_EAB_HMAC": "myhmac",
        }
        cmd = lego._build_lego_run_cmd(
            self._LEGO, conf, self._DOMAINS, "", self._VER, "issue"
        )
        self.assertIn("--eab.kid", cmd)
        self.assertIn("--eab.hmac", cmd)
        self.assertNotIn("--kid", cmd)
        self.assertNotIn("--hmac", cmd)

    def test_hook_uses_deploy_hook_flag(self):
        cmd = self._cmd(hook="systemctl restart nginx", action="renew")
        self.assertIn("--deploy-hook", cmd)
        self.assertNotIn("--run-hook", cmd)


# ---------------------------------------------------------------------------
# _resolve_lego_version
# ---------------------------------------------------------------------------


class TestResolveLegoVersion(unittest.TestCase):
    # A path that can't be exec'd — _lego_version() catches FileNotFoundError
    # and returns (0, 0, 0), letting us exercise the fallback without mocking.
    _MISSING_LEGO = pathlib.Path("/nonexistent/lego")

    def test_override_major_4(self):
        self.assertEqual(lego._resolve_lego_version(self._MISSING_LEGO, "4"), (4, 0, 0))

    def test_override_major_5(self):
        self.assertEqual(lego._resolve_lego_version(self._MISSING_LEGO, "5"), (5, 0, 0))

    def test_override_auto_falls_back_to_detection(self):
        self.assertEqual(
            lego._resolve_lego_version(self._MISSING_LEGO, "auto"), (0, 0, 0)
        )

    def test_no_override_falls_back_to_detection(self):
        self.assertEqual(lego._resolve_lego_version(self._MISSING_LEGO, None), (0, 0, 0))

    def test_invalid_override_falls_back_to_detection(self):
        self.assertEqual(
            lego._resolve_lego_version(self._MISSING_LEGO, "not-a-version"), (0, 0, 0)
        )


# ---------------------------------------------------------------------------
# LEGO_VERSION config schema
# ---------------------------------------------------------------------------


class TestValidateLegoVersion(unittest.TestCase):
    def test_auto_valid(self):
        self.assertIsNone(lego._validate_lego_version("auto"))

    def test_four_valid(self):
        self.assertIsNone(lego._validate_lego_version("4"))

    def test_five_valid(self):
        self.assertIsNone(lego._validate_lego_version("5"))

    def test_other_invalid(self):
        self.assertIsNotNone(lego._validate_lego_version("6"))

    def test_resolves_by_alias(self):
        entry = lego._resolve_config_key("lego-version")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.key, "LEGO_VERSION")


# ---------------------------------------------------------------------------
# _build_status_rows
# ---------------------------------------------------------------------------


class TestBuildStatusRows(unittest.TestCase):
    def _make_info(
        self,
        instance: str | None = "myapp",
        primary: str = "foo.example.com",
        sans: list | None = None,
        expiry_days: int | None = 60,
        state: lego.CertState = lego.CertState.VALID,
        timer_enabled: bool = True,
        timer_active: bool = True,
    ) -> lego.CertInfo:
        expiry = None
        if expiry_days is not None:
            expiry = datetime.datetime.now(datetime.UTC) + datetime.timedelta(
                days=expiry_days
            )
        return lego.CertInfo(
            instance=instance,
            primary_domain=primary,
            sans=sans or [primary],
            expiry=expiry,
            state=state,
            timer_enabled=timer_enabled,
            timer_active=timer_active,
        )

    def test_returns_tuple(self):
        rows, styles = lego._build_status_rows([self._make_info()])
        self.assertIsInstance(rows, list)
        self.assertIsInstance(styles, list)

    def test_row_count_matches_input(self):
        infos = [self._make_info(primary=f"d{i}.example.com") for i in range(3)]
        rows, styles = lego._build_status_rows(infos)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(styles), 3)

    def test_row_has_six_columns(self):
        rows, _ = lego._build_status_rows([self._make_info()])
        self.assertEqual(len(rows[0]), 6)

    def test_instance_column(self):
        rows, _ = lego._build_status_rows([self._make_info(instance="myapp")])
        self.assertEqual(rows[0][0], "myapp")

    def test_unmanaged_instance_dash(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(instance=None, state=lego.CertState.UNMANAGED)]
        )
        self.assertEqual(rows[0][0], "—")

    def test_timer_enabled_active(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(timer_enabled=True, timer_active=True)]
        )
        self.assertEqual(rows[0][5], "enabled / active")

    def test_timer_enabled_inactive(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(timer_enabled=True, timer_active=False)]
        )
        self.assertEqual(rows[0][5], "enabled / inactive")

    def test_timer_disabled(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(timer_enabled=False, timer_active=False)]
        )
        self.assertEqual(rows[0][5], "disabled")

    def test_pending_timer_dash(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(expiry_days=None, state=lego.CertState.PENDING)]
        )
        self.assertEqual(rows[0][5], "—")

    def test_expiry_dash_when_none(self):
        rows, _ = lego._build_status_rows(
            [self._make_info(expiry_days=None, state=lego.CertState.PENDING)]
        )
        self.assertEqual(rows[0][3], "—")
        self.assertEqual(rows[0][4], "—")

    def test_sorted_by_primary_domain(self):
        infos = [
            self._make_info(primary="z.example.com"),
            self._make_info(primary="a.example.com"),
        ]
        rows, _ = lego._build_status_rows(infos)
        self.assertEqual(rows[0][1], "a.example.com")
        self.assertEqual(rows[1][1], "z.example.com")

    def test_style_valid_green(self):
        _, styles = lego._build_status_rows(
            [self._make_info(state=lego.CertState.VALID)]
        )
        self.assertEqual(styles[0], "green")

    def test_style_expiring_soon_yellow(self):
        _, styles = lego._build_status_rows(
            [self._make_info(state=lego.CertState.EXPIRING_SOON)]
        )
        self.assertEqual(styles[0], "yellow")

    def test_style_expiring_critical_bold_red(self):
        _, styles = lego._build_status_rows(
            [self._make_info(state=lego.CertState.EXPIRING_CRITICAL)]
        )
        self.assertEqual(styles[0], "bold red")

    def test_style_expired_bold_red(self):
        _, styles = lego._build_status_rows(
            [self._make_info(state=lego.CertState.EXPIRED)]
        )
        self.assertEqual(styles[0], "bold red")

    def test_style_pending_dim(self):
        _, styles = lego._build_status_rows(
            [self._make_info(state=lego.CertState.PENDING, expiry_days=None)]
        )
        self.assertEqual(styles[0], "dim")


if __name__ == "__main__":
    unittest.main()
