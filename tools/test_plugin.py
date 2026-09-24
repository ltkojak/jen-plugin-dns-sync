#!/usr/bin/env python3
"""
tools/test_plugin.py — the plugin's own unit checks, run by CI after
tools/verify.py. Loads plugin.py with importlib against a stub `jen`
package and fake Flask/flask_login modules so nothing here needs Jen, a
database, or a browser; every check exercises a PURE function of the
plugin with hand-built inputs.

Run: `python3 tools/test_plugin.py` (exit 1 on the first failing check).
"""

import importlib.util
import os
import sys
import types
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _stub_modules():
    """Enough of flask / flask_login for plugin.py to import."""
    flask = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            def deco(fn):
                return fn

            return deco

    flask.Blueprint = Blueprint
    flask.Response = object
    for name in ("flash", "jsonify", "make_response", "redirect", "render_template", "url_for"):
        setattr(flask, name, lambda *a, **k: None)
    flask.request = None
    sys.modules["flask"] = flask
    fl = types.ModuleType("flask_login")
    fl.current_user = types.SimpleNamespace(username="tester", all_subnets=True, role="admin")
    fl.login_required = lambda fn: fn
    sys.modules["flask_login"] = fl


def load_plugin():
    _stub_modules()
    spec = importlib.util.spec_from_file_location("dns_sync_plugin", os.path.join(ROOT, "plugin.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeApp:
    def register_blueprint(self, bp):
        pass


def _stub_jen_plugin_api():
    """A stub `jen`/`jen.plugin_api` sufficient for register(app) to run
    end to end, with register_alert_type enforcing the SAME
    '<plugin_id>_' prefix rule Jen's real one does (jen/services/alerts.py)
    — this is what actually catches a mismatched type_id locally instead
    of only in CI against a real app. Returns the list every
    register_periodic() call is recorded into."""
    periodic_calls = []

    def register_alert_type(plugin_id, type_id, **kwargs):
        prefix = f"{plugin_id}_"
        if not type_id.startswith(prefix):
            raise ValueError(f"type_id {type_id!r} must start with {prefix!r}")

    def register_periodic(plugin_id, name, fn, every_minutes):
        periodic_calls.append((plugin_id, name, fn, every_minutes))

    jen_pkg = types.ModuleType("jen")
    plugin_api = types.ModuleType("jen.plugin_api")
    plugin_api.register_alert_type = register_alert_type
    plugin_api.register_periodic = register_periodic
    plugin_api.subscribe = lambda kind, fn: None
    jen_pkg.plugin_api = plugin_api
    sys.modules["jen"] = jen_pkg
    sys.modules["jen.plugin_api"] = plugin_api
    return periodic_calls


failures = []


def check(cond, msg):
    if cond:
        print(f"ok    {msg}")
    else:
        failures.append(msg)
        print(f"FAIL  {msg}")


def main():
    p = load_plugin()

    # ── name normalisation ───────────────────────────────────────────────────
    check(p.normalize_name("NAS") == ("nas", None), "normalize_name: uppercase lower-cased")
    check(p.normalize_name("my_nas") == ("my-nas", None), "normalize_name: underscore mapped to hyphen")
    check(p.normalize_name("  nas  ") == ("nas", None), "normalize_name: surrounding whitespace stripped")
    name, reason = p.normalize_name("")
    check(name is None and reason == "empty hostname", "normalize_name: empty string refused with a reason")
    name, reason = p.normalize_name("na$s")
    check(name is None and "not a valid DNS label" in reason, "normalize_name: illegal character refused")
    name, reason = p.normalize_name("-nas")
    check(name is None, "normalize_name: leading hyphen refused (not a valid RFC-1123 label)")
    check(p.normalize_name("a" * 63)[0] == "a" * 63, "normalize_name: a 63-char label is the max allowed")
    check(p.normalize_name("a" * 64)[0] is None, "normalize_name: a 64-char label is refused")

    # ── dedupe by ascending IP, lowest IP keeps the bare name ────────────────
    deduped = p.dedupe_names([("10.0.0.5", "nas"), ("10.0.0.2", "nas"), ("10.0.0.9", "printer")])
    check(
        sorted(deduped) == sorted([("10.0.0.5", "nas-2"), ("10.0.0.2", "nas"), ("10.0.0.9", "printer")]),
        f"dedupe_names: lowest IP keeps the bare name, higher IPs get -2, -3 (got {deduped})",
    )
    three_way = p.dedupe_names([("10.0.0.30", "x"), ("10.0.0.10", "x"), ("10.0.0.20", "x")])
    by_ip = dict(three_way)
    check(
        by_ip["10.0.0.10"] == "x" and by_ip["10.0.0.20"] == "x-2" and by_ip["10.0.0.30"] == "x-3",
        f"dedupe_names: a three-way collision suffixes deterministically by ascending IP (got {three_way})",
    )
    no_collision = p.dedupe_names([("10.0.0.1", "a"), ("10.0.0.2", "b")])
    check(no_collision == [("10.0.0.1", "a"), ("10.0.0.2", "b")], "dedupe_names: no collision leaves names untouched")

    # ── build_desired: source priority reservation > lease > ipam ───────────
    desired = p.build_desired(
        {"leases", "reservations", "ipam"},
        leases=[{"ip": "10.0.0.5", "hostname": "from-lease"}, {"ip": "10.0.0.9", "hostname": "lease-only"}],
        reservations=[{"ip": "10.0.0.5", "hostname": "from-reservation"}],
        ipam_entries=[{"ip": "10.0.0.5", "hostname": "from-ipam"}, {"ip": "10.0.0.1", "hostname": "ipam-only"}],
    )
    check(
        desired["10.0.0.5"] == ("from-reservation", "reservation"),
        f"build_desired: reservation beats lease and ipam for the same ip (got {desired['10.0.0.5']})",
    )
    check(desired["10.0.0.9"] == ("lease-only", "lease"), "build_desired: lease-only ip keeps its lease hostname")
    check(desired["10.0.0.1"] == ("ipam-only", "ipam"), "build_desired: ipam-only ip keeps its ipam hostname")
    desired_no_ipam = p.build_desired(
        {"leases"},
        leases=[{"ip": "10.0.0.1", "hostname": "a"}],
        reservations=[],
        ipam_entries=[{"ip": "10.0.0.2", "hostname": "b"}],
    )
    check("10.0.0.2" not in desired_no_ipam, "build_desired: a source not in sources_enabled contributes nothing")

    # ── normalize_desired: chains normalize_name + dedupe_names, keeps source ─
    normd, skipped = p.normalize_desired(
        {"10.0.0.5": ("NAS", "reservation"), "10.0.0.9": ("na$s", "lease"), "10.0.0.2": ("nas", "ipam")}
    )
    check(
        skipped == [("10.0.0.9", "na$s", "'na$s' is not a valid DNS label")],
        f"normalize_desired: invalid raw name skipped with a reason (got {skipped})",
    )
    check(
        normd == {"nas": ("10.0.0.2", "ipam"), "nas-2": ("10.0.0.5", "reservation")},
        f"normalize_desired: collision suffixed after normalisation, source preserved per ip (got {normd})",
    )

    # ── the planner + the foreign-record invariant ───────────────────────────
    plan = p.plan_sync(
        desired={"nas": "10.0.0.5", "printer": "10.0.0.9"},
        ledger={"nas": "10.0.0.5", "old-host": "10.0.0.1"},
        remote={"nas": "10.0.0.5", "someone-elses-record": "10.0.0.77"},
    )
    check(
        plan["add"] == [("printer", "10.0.0.9")],
        f"plan_sync: a name in desired but not the ledger is an add (got {plan['add']})",
    )
    check(plan["update"] == [], "plan_sync: unchanged desired/ledger/remote produces no update")
    check(
        plan["remove"] == ["old-host"], f"plan_sync: a ledger name no longer desired is a remove (got {plan['remove']})"
    )
    check(
        "someone-elses-record" not in plan["remove"],
        "plan_sync: THE INVARIANT — a foreign record in `remote` but not `ledger` is never proposed for removal",
    )
    ip_changed = p.plan_sync(desired={"nas": "10.0.0.6"}, ledger={"nas": "10.0.0.5"}, remote={"nas": "10.0.0.5"})
    check(ip_changed["update"] == [("nas", "10.0.0.6")], "plan_sync: a changed ip for an existing name is an update")
    drifted = p.plan_sync(desired={"nas": "10.0.0.5"}, ledger={"nas": "10.0.0.5"}, remote={})
    check(
        drifted["update"] == [("nas", "10.0.0.5")],
        "plan_sync: ledger matches desired but the remote record vanished -> re-propose as an update",
    )

    # ── Pi-hole hosts-line parser ─────────────────────────────────────────────
    check(
        p.parse_pihole_hosts_line("10.0.0.5 nas") == ("10.0.0.5", "nas"), "parse_pihole_hosts_line: a well-formed line"
    )
    check(
        p.parse_pihole_hosts_line("  10.0.0.5   nas  ") == ("10.0.0.5", "nas"),
        "parse_pihole_hosts_line: surrounding/extra whitespace tolerated",
    )
    check(
        p.parse_pihole_hosts_line("not-an-ip nas") is None, "parse_pihole_hosts_line: a non-IP first field is refused"
    )
    check(
        p.parse_pihole_hosts_line("10.0.0.5") is None, "parse_pihole_hosts_line: a line with only one field is refused"
    )
    check(
        p.parse_pihole_hosts_line("10.0.0.5 two words") is None,
        "parse_pihole_hosts_line: more than two fields is refused",
    )
    check(p.parse_pihole_hosts_line("") is None, "parse_pihole_hosts_line: an empty line is refused")
    check(
        p.format_pihole_hosts_line("10.0.0.5", "nas") == "10.0.0.5 nas",
        "format_pihole_hosts_line: the inverse of the parser",
    )
    round_trip = p.parse_pihole_hosts_line(p.format_pihole_hosts_line("10.0.0.5", "nas"))
    check(round_trip == ("10.0.0.5", "nas"), "parse/format_pihole_hosts_line: round-trips")

    # ── AdGuard FQDN + Unbound export ─────────────────────────────────────────
    check(p.adguard_fqdn("nas", "lan") == "nas.lan", "adguard_fqdn: name + domain joined with a dot")
    export = p.unbound_export({"printer": "10.0.0.9", "nas": "10.0.0.5"}, "lan")
    check(
        export == 'local-data: "nas.lan. IN A 10.0.0.5"\nlocal-data: "printer.lan. IN A 10.0.0.9"\n',
        f"unbound_export: sorted, trailing-dot FQDN, one local-data line per record (got {export!r})",
    )
    check(p.unbound_export({}, "lan") == "", "unbound_export: no records is an empty string, not a stray newline")

    # ── debounce: a touch pushes the fire time out; ready only once quiet ────
    now = datetime(2026, 9, 24, 12, 0, 0)
    pending = p.debounce_schedule({}, 1, now, delay_s=10)
    check(pending == {1: now + timedelta(seconds=10)}, "debounce_schedule: first touch schedules delay_s out")
    pending = p.debounce_schedule(pending, 1, now + timedelta(seconds=5), delay_s=10)
    check(
        pending[1] == now + timedelta(seconds=15),
        f"debounce_schedule: a second touch during the window pushes the fire time further out (got {pending[1]})",
    )
    ready, remaining = p.debounce_ready(pending, now + timedelta(seconds=10))
    check(ready == [] and remaining == pending, "debounce_ready: not ready before its (pushed-out) fire time")
    ready, remaining = p.debounce_ready(pending, now + timedelta(seconds=15))
    check(ready == [1] and remaining == {}, "debounce_ready: ready exactly at its fire time, and removed from pending")
    multi = p.debounce_schedule(p.debounce_schedule({}, 1, now, 5), 2, now, 20)
    ready, remaining = p.debounce_ready(multi, now + timedelta(seconds=6))
    check(ready == [1] and 2 in remaining, "debounce_ready: only the target whose window has closed is ready")

    # ── subnet scope resolution at save time ──────────────────────────────────
    check(
        p.resolve_subnet_ids(None, {3, 1, 2}) == [1, 2, 3],
        "resolve_subnet_ids: 'all' resolves to the accessible set, sorted",
    )
    check(
        p.resolve_subnet_ids([1, 99], {1, 2}) == [1],
        "resolve_subnet_ids: an explicit selection is intersected with accessible",
    )
    check(
        p.resolve_subnet_ids([], {1, 2}) == [], "resolve_subnet_ids: an explicit empty selection stays empty, not 'all'"
    )

    # ── write gate — viewers can look at DNS Sync but not change it ─────────
    p.current_user.role = "viewer"
    check(p._is_admin() is False, "a viewer is not admin")
    check(p._require_write() is False, "a viewer cannot write")
    for fn, args in (
        (p.add_target, ()),
        (p.toggle_target, (1,)),
        (p.delete_target, (1,)),
    ):
        try:
            fn(*args)
            gated = True
        except Exception:
            gated = False
        check(gated, f"{fn.__name__} refuses a viewer before touching the request")
    p.current_user.role = "admin"
    check(p._is_admin() is True, "admin role restored for the rest of the run")

    # ── register(): actually runs end to end against a stub jen.plugin_api ──
    # (the real v1.0.1 bug: register_alert_type(PLUGIN_ID, "dns_sync_failed",
    # ...) didn't start with "dns-sync_" — PLUGIN_ID has a hyphen, the type_id
    # was all-underscore — and Jen's real register_alert_type raises on that
    # mismatch, so the plugin never loaded at all; caught here by enforcing
    # the same rule the stub's register_alert_type does)
    periodic_calls = _stub_jen_plugin_api()
    try:
        p.register(_FakeApp())
        registered = True
    except Exception as e:
        registered = False
        print(f"      register() raised: {e}")
    check(registered, "register(): runs end to end without raising against a real-rule stub")
    tick_calls = [c for c in periodic_calls if c[1] == "reconcile"]
    check(
        len(tick_calls) == 1 and tick_calls[0][3] == 15,
        f"register(): the reconcile tick is registered every 15 minutes (got {tick_calls})",
    )

    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall plugin checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
