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
    plugin_api.can_access_subnet = lambda subnet_id, *, allow_unattributed=False: True
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


class _Form(dict):
    def getlist(self, key):
        v = self.get(key)
        return [] if v is None else [v] if isinstance(v, str) else list(v)


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

    # ── 1.0.2: the domain suffix is validated as DNS labels ──────────────────
    check(p.normalize_domain("") == ("lan", None), "normalize_domain: blank is the default `lan`")
    check(
        p.normalize_domain("  Home.Example.  ") == ("home.example", None), "normalize_domain: lower-cased, dots trimmed"
    )
    for bad in ("a..b", "lan; rm -rf", "-lan", "a b", "x" * 64, "ok." + "y" * 64):
        dom, reason = p.normalize_domain(bad)
        check(dom is None and reason, f"normalize_domain: {bad[:20]!r} is refused with a reason")
    check(p.normalize_domain("a" * 63)[0] == "a" * 63, "normalize_domain: 63 characters still fits the column")

    # ── 1.0.2: the two subnet predicates a target is judged by ────────────────
    only_one = lambda sid: sid == 1  # noqa: E731 - a subnet-restricted caller: subnet 1 only, None is not theirs
    everything = lambda sid: True  # noqa: E731 - an unrestricted caller
    check(
        p.target_visible([1, 2, 3], only_one) is True, "target_visible: ONE accessible subnet is enough to see a target"
    )
    check(p.target_visible([2, 3], only_one) is False, "target_visible: a target in no accessible subnet is invisible")
    check(
        p.target_visible([], only_one) is False, "target_visible: a target with no subnet is not a restricted caller's"
    )
    check(p.target_visible([], everything) is True, "target_visible: an unrestricted caller sees every target")
    check(
        p.target_manageable([1, 2, 3], only_one) is False, "target_manageable: needs EVERY subnet, not an intersection"
    )
    check(p.target_manageable([1], only_one) is True, "target_manageable: a target wholly inside the caller's subnets")
    check(p.target_manageable([], only_one) is False, "target_manageable: a target with no subnet is unrestricted-only")
    check(
        p.target_manageable([], everything) is True, "target_manageable: an unrestricted caller manages an empty scope"
    )

    # ── 1.0.2: an update REMOVES the stale record, then adds ─────────────────
    class Remote:
        """Pi-hole/AdGuard in miniature: a SET of (name, ip) lines — it keeps whatever it is given."""

        def __init__(self, lines):
            self.lines = set(lines)
            self.fail_remove = set()
            self.fail_add = set()

        def add(self, name, ip):
            if name in self.fail_add:
                raise p._SyncError("add refused")
            self.lines.add((name, ip))

        def remove(self, name, ip):
            if name in self.fail_remove:
                raise p._SyncError("remove refused")
            self.lines.discard((name, ip))

    remote = Remote({("nas", "10.0.0.5"), ("foreign", "10.0.0.77")})
    ledger = {"nas": "10.0.0.5"}
    plan = p.plan_sync({"nas": "10.0.0.6"}, ledger, {"nas": "10.0.0.5", "foreign": "10.0.0.77"})
    ups, rems, errs = p.apply_plan(plan, ledger, {"nas": "reservation"}, remote.add, remote.remove)
    check(
        remote.lines == {("nas", "10.0.0.6"), ("foreign", "10.0.0.77")},
        f"apply_plan: after an IP change the remote holds exactly ONE nas record and the foreign one is untouched (got {remote.lines})",
    )
    check(
        ups == [("nas", "10.0.0.6", "reservation")] and rems == ["nas"] and not errs,
        "apply_plan: reports the removal and the add",
    )

    remote = Remote({("nas", "10.0.0.5")})
    remote.fail_remove = {"nas"}
    ups, rems, errs = p.apply_plan(plan, ledger, {}, remote.add, remote.remove)
    check(
        remote.lines == {("nas", "10.0.0.5")},
        "apply_plan: a failed removal leaves the remote as it was — no second record is added",
    )
    check(not ups and not rems and len(errs) == 1, "apply_plan: a failed removal reports an error and delivers nothing")

    remote = Remote({("nas", "10.0.0.5")})
    remote.fail_add = {"nas"}
    ups, rems, errs = p.apply_plan(plan, ledger, {}, remote.add, remote.remove)
    check(
        not ups and rems == ["nas"] and len(errs) == 1,
        "apply_plan: removed but not added -> reported removed so the ledger row goes and the next sync is a plain add",
    )

    remote = Remote({("old", "10.0.0.1"), ("foreign", "10.0.0.9")})
    plan = p.plan_sync({}, {"old": "10.0.0.1"}, {"old": "10.0.0.1", "foreign": "10.0.0.9"})
    ups, rems, errs = p.apply_plan(plan, {"old": "10.0.0.1"}, {}, remote.add, remote.remove)
    check(
        remote.lines == {("foreign", "10.0.0.9")} and rems == ["old"],
        "apply_plan: a plain removal still removes only the ledger's record",
    )

    # ── a fake database, to see what the impure functions actually do ────────
    class FakeDB:
        def __init__(self, selects=None):
            self.statements = []
            self.selects = list(selects or [])
            self.committed = False

        def cursor(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            self.statements.append((sql.split()[0].upper(), sql, params))

        def fetchone(self):
            return self.selects.pop(0) if self.selects else None

        def fetchall(self):
            return self.selects.pop(0) if self.selects else []

        def commit(self):
            self.committed = True

        def close(self):
            pass

    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._update_ledger(7, [("nas", "10.0.0.6", "lease")], ["nas"])
    kinds = [s[0] for s in fdb.statements]
    check(
        kinds == ["DELETE", "INSERT"] and fdb.committed,
        f"_update_ledger: removals are applied BEFORE upserts, so an update leaves the new row (got {kinds})",
    )

    # ── 1.0.2: one Pi-hole session per sync, logged out at the end ───────────
    calls = []
    real_http, real_sid = p._http_call, p._pihole_sid
    p._http_call = lambda method, url, **kw: (calls.append((method, url, kw.get("headers"))), (204, None))[1]
    p._pihole_sid = lambda target: "SID123"
    pihole = {"kind": "pihole", "url": "http://pi.hole", "allow_self_signed": 0}
    with p._remote_session(pihole) as sid:
        seen = sid
    check(seen == "SID123", "_remote_session: yields the one Pi-hole session id")
    check(
        calls == [("DELETE", "http://pi.hole/api/auth", {"X-FTL-SID": "SID123"})],
        f"_remote_session: logs the session out with DELETE /api/auth on the way out (got {calls})",
    )
    calls.clear()
    try:
        with p._remote_session(pihole):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    check(len(calls) == 1, "_remote_session: still logs out when the sync body raises")
    calls.clear()
    with p._remote_session({"kind": "adguard", "url": "http://ag", "allow_self_signed": 0}) as sid:
        seen = sid
    check(seen is None and calls == [], "_remote_session: AdGuard Home has no session to open or close")
    p._pihole_sid = lambda target: None
    calls.clear()
    with p._remote_session(pihole):
        pass
    check(calls == [], "_remote_session: a Pi-hole with no password (no sid) has nothing to log out")
    p._http_call, p._pihole_sid = real_http, real_sid

    # ── 1.0.2: a failed remote fetch aborts the sync ─────────────────────────
    target = {
        "id": 4,
        "name": "pi",
        "kind": "adguard",
        "url": "http://ag",
        "enabled": 1,
        "previewed_at": "x",
        "domain": "lan",
    }
    p._get_db = lambda: FakeDB([target])
    p._desired_for_target = lambda t: ({"a": "10.0.0.1"}, {"a": "lease"}, [])
    p._ledger_for_target = lambda tid: ({}, [])
    applied, recorded, alerted = [], [], []

    def broken_fetch(t, sid=None):
        raise p._SyncError("connection refused")

    p._fetch_remote = broken_fetch
    p._apply_add = lambda t, sid, name, ip: applied.append((name, ip))
    p._apply_remove = lambda t, sid, name, ip: applied.append((name, ip))
    p._record_sync_result = lambda tid, msg: recorded.append((tid, msg))
    p._maybe_alert = lambda t, msg: alerted.append(msg)
    p._sync_locked(4)
    check(applied == [], "_sync_locked: a failed fetch of the remote list makes NO per-record call")
    check(
        recorded == [(4, "connection refused")] and alerted == ["connection refused"],
        "_sync_locked: the failure is recorded and alerted once",
    )

    # ── 1.0.2: a per-target lock — two runs never overlap ────────────────────
    ran = []
    p._sync_locked = lambda tid: ran.append(tid)
    lock = p._lock_for(4)
    lock.acquire()
    p._sync_one_target(4)
    check(ran == [], "_sync_one_target: skips a run while the same target is already syncing")
    lock.release()
    p._sync_one_target(4)
    check(
        ran == [4] and not p._lock_for(4).locked(),
        "_sync_one_target: runs when the target is free and releases the lock after",
    )
    p._sync_one_target(5)
    check(ran == [4, 5], "_sync_one_target: a lock on one target never holds up another")

    # ── 1.0.2: who may do what to a target (the routes, restricted callers) ──
    p._require_write = lambda: True
    p.flash = lambda msg, cat="message": flashed.append(msg)
    p.redirect = lambda where: "redirect"
    p.url_for = lambda *a, **k: "/"
    p.jsonify = lambda payload: payload
    p.Response = lambda body, status=200, **k: (body, status)
    flashed = []
    boom_db = lambda: (_ for _ in ()).throw(AssertionError("the database was touched"))  # noqa: E731
    p._touch_target = lambda tid: None
    row_b = {"id": 9, "subnet_ids": "[2]", "enabled": 0, "previewed_at": "x", "domain": "lan"}
    row_mixed = {"id": 9, "subnet_ids": "[1, 2]", "enabled": 0, "previewed_at": "x", "domain": "lan"}
    p._can = only_one

    p._load_target = lambda tid: row_b
    p._get_db = boom_db
    check(
        p.toggle_target(9) == "redirect" and "not found" in flashed[-1].lower(),
        "toggle: a target in subnets the caller has no access to reads as not found",
    )
    p._load_target = lambda tid: row_mixed
    check(
        p.toggle_target(9) == "redirect" and "cannot access" in flashed[-1],
        "toggle: a target that reaches an inaccessible subnet cannot be changed (all-known rule)",
    )
    check(
        p.preview_target(9) == ({"error": "this target covers subnets you cannot access"}, 403),
        "preview: the same all-known rule, refused with 403 and no stamp",
    )
    p._load_target = lambda tid: row_b
    check(p.preview_target(9) == ({"error": "not found"}, 404), "preview: an invisible target is a 404")
    check(p.target_records(9) == ({"error": "not found"}, 404), "records: an invisible target is a 404")
    check(p.export_unbound(9) == ("Target not found.", 404), "export: an invisible target is a 404")
    p._load_target = lambda tid: {"id": 9, "subnet_ids": "[1]", "enabled": 0, "previewed_at": "x", "domain": "lan"}
    check(
        p.delete_target(9) == "redirect" and "every subnet" in flashed[-1],
        "delete: needs an account that can see every subnet, even for a target wholly in the caller's",
    )
    check(
        p.add_target() == "redirect" and "every subnet" in flashed[-1],
        "add: a subnet-restricted account cannot create a target",
    )

    fdb = FakeDB()
    p._get_db = lambda: fdb
    p._load_target = lambda tid: {"id": 9, "subnet_ids": "[1]", "enabled": 0, "previewed_at": "x", "domain": "lan"}
    check(
        p.toggle_target(9) == "redirect" and any(s[0] == "UPDATE" for s in fdb.statements),
        "toggle: a target wholly inside the caller's subnets is theirs to change",
    )
    p._can = everything
    fdb = FakeDB()
    p._get_db = lambda: fdb
    check(
        p.delete_target(9) == "redirect" and any(s[0] == "DELETE" for s in fdb.statements),
        "delete: an unrestricted admin removes it",
    )

    # ── 1.0.2: record views are filtered row by row (the list AND the export) ─
    rows = [
        {"name": "mine", "ip": "10.1.0.5", "source": "lease"},
        {"name": "theirs", "ip": "10.2.0.5", "source": "lease"},
        {"name": "nowhere", "ip": "172.16.0.5", "source": "lease"},
    ]
    p._ledger_for_target = lambda tid: ({r["name"]: r["ip"] for r in rows}, rows)
    p._subnet_map = lambda: {1: {"cidr": "10.1.0.0/24"}, 2: {"cidr": "10.2.0.0/24"}}
    p._can = only_one
    p._load_target = lambda tid: {"id": 9, "subnet_ids": "[1, 2]", "enabled": 1, "previewed_at": "x", "domain": "lan"}
    body, status = p.export_unbound(9)
    check(
        status == 200 and "mine.lan" in body and "theirs" not in body and "nowhere" not in body,
        "export: a restricted caller's export holds only their subnets' records",
    )
    check(
        [r["name"] for r in p._visible_records(9)] == ["mine"],
        "records: a record in no known subnet is not a restricted caller's",
    )
    p._can = everything
    check(
        [r["name"] for r in p._visible_records(9)] == ["mine", "theirs", "nowhere"],
        "records: an unrestricted caller sees every record",
    )
    body, status = p.export_unbound(9)
    check("theirs.lan" in body and "nowhere.lan" in body, "export: an unrestricted caller's export is the whole ledger")

    # ── 1.0.3: a database failure never reaches the page ─────────────────────
    def db_down(*a, **k):
        raise RuntimeError("Access denied for user 'jen'@'10.9.9.9' marker-q96")

    flashed.clear()
    p._can = everything
    p._require_write = lambda: True
    p._accessible_subnets = lambda: {1: {}}
    p._get_db = db_down
    p.request = types.SimpleNamespace(
        form={
            "name": "x",
            "kind": "pihole",
            "url": "http://192.0.2.9",
            "domain": "lan",
            "sources": "leases",
            "scope_all": "on",
        },
        args={},
    )
    p.request.form = _Form(p.request.form)
    p.add_target()
    check(
        flashed and all("marker-q96" not in m and "10.9.9.9" not in m for m in flashed) and "Jen's log" in flashed[-1],
        f"add_target: a database failure shows a generic message and no exception text (got {flashed})",
    )

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
