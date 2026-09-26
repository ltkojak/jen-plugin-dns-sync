"""
Local DNS Sync plugin for Jen.
Pushes DHCP names (from active leases, reservations, and IPAM Lite
entries) into a Pi-hole or AdGuard Home local DNS server, so a name
like `nas.lan` resolves on the LAN without Kea DDNS — which assumes a
BIND-style server most homelabs don't run. Unbound has no write API,
so a target-less "Export Unbound local-data" download covers it.
Version lives in manifest.json — not duplicated here.

Verify-first (read 2026-09-24, pinned here per CLAUDE.md's round-5
recipe — every path/payload below is quoted from the vendor's own
source, not a blog post or a guess):

Pi-hole v6 (FTL) — OpenAPI source, not the rendered docs (which are a
JS app the doc-reading tool can't execute): github.com/pi-hole/FTL,
`src/api/docs/content/specs/{auth,config}.yaml` @ master, 2026-09-24.
  * `POST {url}/api/auth` body `{"password": "<pw>"}` -> `{"session":
    {"valid": bool, "sid": "<token>"|null, "csrf": "<token>"|null,
    "validity": <seconds>, "message": "<str>"}}`. `sid` is null and
    `valid` may still be true when the box has no password set.
  * Session auth via header `X-FTL-SID: <sid>` (one of four accepted
    auth methods — `auth.yaml`'s `x_header_sid` scheme). No CSRF
    header needed with header-based auth; CSRF is for cookie auth only
    ("it's not needed with other authentication methods" per the
    endpoint's own description).
  * `config.yaml`: the URL template is literally `/config/{element}/
    {value}` (`main.yaml` lines 240-244) — `{element}` itself contains
    a literal `/`, e.g. `dns/hosts`, so the real path has three
    segments after `/api/config/`: `dns/hosts/<value>`.
  * `GET {url}/api/config/dns/hosts` -> `{"config": {"dns": {"hosts":
    ["<ip> <name>", ...]}}}` — each entry is one space-separated
    string, exactly as `docs.pi-hole.net` community threads describe
    and the OpenAPI `config` schema's own `dns.hosts` example
    (`"192.168.2.123 mymusicbox"`) confirms.
  * `PUT {url}/api/config/dns/hosts/<urlencoded "ip name">` -> 201, no
    body ("Add config array item"). `DELETE` the same path -> 204.
    There is no per-item update; Pi-hole hosts lines are changed by
    deleting the old string and adding the new one.
  * `DELETE {url}/api/auth` (same `X-FTL-SID` header) -> 204 "delete the
    current session" (404 when none is active) — `auth.yaml`, re-read
    2026-09-25 for 1.0.2. A sync opens ONE session and logs it out at
    the end instead of leaving one per call to expire on its own.

AdGuard Home — `openapi/openapi.yaml` @ master, github.com/
AdguardTeam/AdGuardHome, 2026-09-24. `servers: [{url: /control}]`,
`security: [{basicAuth: []}]` (standard HTTP Basic).
  * `GET {url}/control/rewrite/list` -> `RewriteEntry[]`, each
    `{"domain": "<fqdn>", "answer": "<ip-or-cname>", "enabled": bool}`.
  * `POST {url}/control/rewrite/add` body `RewriteEntry` `{"domain":
    "<fqdn>", "answer": "<ip>"}` -> 200.
  * `POST {url}/control/rewrite/delete` body `RewriteEntry` (same
    shape, matched by both fields) -> 200.
  * `PUT {url}/control/rewrite/update` body `{"target": RewriteEntry,
    "update": RewriteEntry}` exists too; this plugin uses delete+add
    uniformly across both backends instead (one code path, one extra
    HTTP call on an update — acceptable at homelab scale).
  AdGuard rewrites carry the full domain per record (no server-side
  suffix expansion the way Pi-hole's `expandHosts` does), so this
  plugin builds `"<name>.<target.domain>"` for every AdGuard call.

Design notes
────────────
**The ledger.** `ds_records` is the only truth this plugin acts on:
`plan_sync()` below only ever proposes removing a name that is IN THE
LEDGER. A record on the remote server that Jen did not create is never
touched, even if it's absent from the desired set and even if the
remote list is fetched and inspected for drift detection.

**Debounce.** `debounce_schedule`/`debounce_ready` model "a touch
pushes a target's fire time `delay_s` out" — repeated touches during a
burst keep pushing it out, coalescing into one sync after the burst
quiets down. The live wiring (`_touch_target`/`_fire_debounced_sync`)
is a plain per-target `threading.Timer`, cancelled and rescheduled on
each touch; no thread is ever created at import or register() time —
only later, from inside a real `subscribe()` callback on Jen's already-
running event dispatcher, so this never fights `create_app()`'s "starts
nothing" rule the way a raw always-on loop would.

**Who may do what (1.0.2).** A target is an ALL-KNOWN object: acting on it needs every
subnet it lists (`target_manageable`), creating or deleting one needs an account that can
see every subnet, and only seeing it and its records is scoped (`target_visible` and a
per-record filter by where each address lives). Every by-id route judges the target's own
subnets, never a value the caller typed.

**Mandatory preview.** A target is created `enabled=0`. The Preview
action runs the planner without applying anything and stamps
`previewed_at`; the Enable toggle refuses (flash, no state change) when
`previewed_at IS NULL` — a target genuinely cannot go live without an
operator having seen what it would do first.
"""

import contextlib
import ipaddress
import json
import logging
import os as _os
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

PLUGIN_ID = "dns-sync"

bp = Blueprint(
    "dns_sync",
    __name__,
    template_folder="templates",
    root_path=_os.path.dirname(_os.path.abspath(__file__)),
    url_prefix="/network/dns-sync",
)

_KINDS = ("pihole", "adguard")
_SOURCES = ("leases", "reservations", "ipam")

_HTTP_TIMEOUT_S = 10
_DEBOUNCE_DELAY_S = 10
_ALERT_COOLDOWN_S = 3600

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_PIHOLE_HOSTS_LINE_RE = re.compile(r"^(\S+)\s+(\S+)$")

_EVENT_KINDS = (
    "lease.new",
    "lease.expired",
    "lease.hostname_changed",
    "lease.ip_changed",
    "reservation.added",
    "reservation.changed",
    "reservation.deleted",
)


class _SyncError(Exception):
    pass


# ── Pure: name normalisation, the planner, the Pi-hole line format ─────────────


def normalize_name(raw):
    """Pure: an RFC-1123 DNS label -> (name, None) | (None, reason).
    Lower-cases and maps '_' to '-' (a common hostname habit that isn't
    valid DNS); anything that still doesn't fit a single label after
    that is refused rather than mangled further."""
    s = (raw or "").strip().lower().replace("_", "-")
    if not s:
        return None, "empty hostname"
    if not _LABEL_RE.match(s):
        return None, f"{raw!r} is not a valid DNS label"
    return s, None


def dedupe_names(candidates):
    """Pure: [(ip, name)] -> [(ip, name)] with same-name collisions
    across DIFFERENT ips suffixed -2, -3, ... deterministically by
    ascending IP order (the lowest IP keeps the bare name). Candidates
    that already share both ip and name are left as plain duplicates —
    callers building from a dict never produce those."""
    by_name: dict[str, list[str]] = {}
    for ip, name in candidates:
        by_name.setdefault(name, []).append(ip)
    suffix_for = {}
    for name, ips in by_name.items():
        if len(set(ips)) <= 1:
            continue
        ordered = sorted(set(ips), key=lambda s: ipaddress.IPv4Address(s))
        for i, ip in enumerate(ordered):
            if i > 0:
                suffix_for[(name, ip)] = i + 1
    out = []
    for ip, name in candidates:
        suf = suffix_for.get((name, ip))
        out.append((ip, f"{name}-{suf}" if suf else name))
    return out


def build_desired(sources_enabled, leases, reservations, ipam_entries):
    """Pure: merge candidate lists (each `[{"ip", "hostname"}]`) from up
    to three sources into one `{ip: (raw_hostname, source)}`. When the
    same ip appears in more than one enabled source, priority is
    reservation > lease > ipam — a reservation is the operator's own
    stated intent for that address, so it wins; applied by iterating
    lowest-priority first so a later source's assignment overwrites an
    earlier one. `source` is carried through so the ledger can record
    where each record actually came from."""
    out = {}
    if "ipam" in sources_enabled:
        for e in ipam_entries:
            if e.get("hostname"):
                out[e["ip"]] = (e["hostname"], "ipam")
    if "leases" in sources_enabled:
        for e in leases:
            if e.get("hostname"):
                out[e["ip"]] = (e["hostname"], "lease")
    if "reservations" in sources_enabled:
        for e in reservations:
            if e.get("hostname"):
                out[e["ip"]] = (e["hostname"], "reservation")
    return out


def normalize_desired(raw_desired):
    """Pure: `{ip: (raw_hostname, source)}` -> (`{name: (ip, source)}`,
    `[(ip, raw, reason)]` skipped). Chains normalize_name then
    dedupe_names — the one call site both routes below actually use."""
    normalized = []  # [(ip, name)]
    source_by_ip = {}
    skipped = []
    for ip, (raw, source) in raw_desired.items():
        name, reason = normalize_name(raw)
        if name is None:
            skipped.append((ip, raw, reason))
            continue
        normalized.append((ip, name))
        source_by_ip[ip] = source
    deduped = dedupe_names(normalized)
    return {name: (ip, source_by_ip[ip]) for ip, name in deduped}, skipped


def plan_sync(desired, ledger, remote):
    """Pure. `desired`/`ledger`/`remote` are all `{name: ip}`. Returns
    `{"add": [(name, ip)], "update": [(name, ip)], "remove": [name]}`.

    The foreign-record invariant: `remove` is built ONLY from names in
    `ledger` (Jen's own history for this target) that have fallen out
    of `desired` — `remote` is never iterated for removals, so a
    record Jen never created (present in `remote`, absent from
    `ledger`) can never appear in `remove` no matter what it contains."""
    add, update = [], []
    for name, ip in desired.items():
        if name not in ledger:
            add.append((name, ip))
        elif ledger[name] != ip or remote.get(name) != ip:
            update.append((name, ip))
    remove = [name for name in ledger if name not in desired]
    return {"add": add, "update": update, "remove": remove}


def parse_pihole_hosts_line(line):
    """Pure: `"<ip> <name>"` -> `(ip, name)` | `None` if malformed or
    the ip isn't a valid IPv4 address."""
    m = _PIHOLE_HOSTS_LINE_RE.match((line or "").strip())
    if not m:
        return None
    ip, name = m.group(1), m.group(2)
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    return ip, name


def format_pihole_hosts_line(ip, name):
    """Pure: the inverse of parse_pihole_hosts_line."""
    return f"{ip} {name}"


def pihole_hosts_value_path(ip, name):
    """Pure: the URL-encoded `{value}` path segment for the Pi-hole
    `config_elem_value` add/delete endpoints."""
    return urllib.parse.quote(format_pihole_hosts_line(ip, name), safe="")


def adguard_fqdn(name, domain):
    """Pure: the full domain AdGuard rewrites need (no server-side
    suffix expansion the way Pi-hole's expandHosts has)."""
    return f"{name}.{domain}"


def unbound_export(records, domain):
    """Pure: Unbound `local-data:` lines for `{name: ip}`, one A record
    per ledger entry, sorted by name for a stable diff-able download."""
    lines = [f'local-data: "{name}.{domain}. IN A {ip}"' for name, ip in sorted(records.items())]
    return ("\n".join(lines) + "\n") if lines else ""


def debounce_schedule(pending, target_id, now, delay_s=_DEBOUNCE_DELAY_S):
    """Pure: `pending` (`{target_id: fire_at}`) with `target_id`'s fire
    time pushed to `now + delay_s`. A burst of touches inside the delay
    window keeps pushing it further out — the sync only actually fires
    once the burst has been quiet for `delay_s`."""
    out = dict(pending)
    out[target_id] = now + timedelta(seconds=delay_s)
    return out


def debounce_ready(pending, now):
    """Pure: (ready_ids, remaining_pending) split by fire time <= now.
    `ready_ids` is sorted for deterministic test assertions."""
    ready = sorted(tid for tid, at in pending.items() if at <= now)
    remaining = {tid: at for tid, at in pending.items() if at > now}
    return ready, remaining


def resolve_subnet_ids(selected, accessible):
    """Pure: what gets stored in `ds_targets.subnet_ids` at save time.
    `selected=None` means "all accessible to me" — resolved to the
    explicit list NOW, not re-derived at sync time (a periodic job has
    no "current user" to re-derive it against). An explicit `selected`
    is intersected with `accessible` so a target can never be saved
    scoped to a subnet its creator couldn't see."""
    if selected is None:
        return sorted(accessible)
    return sorted(set(selected) & set(accessible))


def normalize_domain(raw):
    """Pure: the domain suffix a target appends to every name -> (domain,
    None) | (None, reason). Blank means the default `lan`. Every dot-separated
    part must be a DNS label (the same rule host labels obey) and the whole
    thing must fit `ds_targets.domain` (VARCHAR(63)); the old code cut the
    text at 63 characters and stored whatever was left, so `lan; rm -rf` or
    `a..b` went straight into a record name and an AdGuard rewrite."""
    s = (raw or "").strip().lower().strip(".")
    if not s:
        return "lan", None
    if len(s) > 63:
        return None, "the domain suffix is longer than 63 characters"
    for label in s.split("."):
        if not _LABEL_RE.match(label):
            return None, f"{raw!r} is not a valid domain suffix (letters, digits and hyphens, dot-separated)"
    return s, None


def target_visible(subnet_ids, can):
    """Pure: may this caller SEE that a target exists and read its records?
    `can(subnet_id)` is the caller's own subnet predicate, `can(None)` is True
    only for an unrestricted caller. Any one accessible subnet is enough to see
    the target; the record list is still filtered row by row."""
    if can(None):
        return True
    return any(can(sid) for sid in subnet_ids)


def target_manageable(subnet_ids, can):
    """Pure: may this caller ACT on the target (preview, enable, pause)? A DNS
    Sync target is an all-known object: it pushes the names of EVERY subnet it
    lists, so acting on it needs every one of them. A target that lists no
    subnet at all is the unrestricted caller's."""
    if not subnet_ids:
        return bool(can(None))
    return all(can(sid) for sid in subnet_ids)


def apply_plan(plan, ledger, source_by_name, add_fn, remove_fn):
    """Impure only through the two callables. Carries out `plan_sync`'s plan and
    reports what was DELIVERED: `(upserts [(name, ip, source)], removes [name],
    errors [str])`.

    An update is a removal of the record the ledger holds (the old IP) followed
    by the add of the new one. Pi-hole keeps every `"ip name"` line it is given
    and AdGuard every rewrite, so adding alone left the stale record answering
    next to the new one, and the ledger — by then holding the new IP — could
    never clean it. If the removal fails the add is NOT attempted (the ledger
    still says what is on the server); if the removal succeeded and the add
    failed, the name is reported removed so the ledger row goes and the next
    sync retries a plain add."""
    upserts, removes, errors = [], [], []
    for name, ip in plan["add"]:
        try:
            add_fn(name, ip)
            upserts.append((name, ip, source_by_name.get(name, "lease")))
        except _SyncError as e:
            errors.append(f"{name}: {e}")
    for name, ip in plan["update"]:
        old_ip = ledger.get(name)
        if old_ip and old_ip != ip:
            try:
                remove_fn(name, old_ip)
                removes.append(name)
            except _SyncError as e:
                errors.append(f"{name}: {e}")
                continue
        try:
            add_fn(name, ip)
            upserts.append((name, ip, source_by_name.get(name, "lease")))
        except _SyncError as e:
            errors.append(f"{name}: {e}")
    for name in plan["remove"]:
        try:
            remove_fn(name, ledger.get(name))
            removes.append(name)
        except _SyncError as e:
            errors.append(f"{name}: {e}")
    return upserts, removes, errors


# ── DB helpers (same shape as every other bundled plugin) ──────────────────────


def _get_db():
    from jen.plugin_api import get_jen_db

    return get_jen_db()


def _get_kea_db():
    from jen.plugin_api import get_kea_db

    return get_kea_db()


def _subnet_map():
    from jen.plugin_api import subnet_map

    return subnet_map()


def _accessible_subnets():
    from jen.plugin_api import get_accessible_subnet_map

    return get_accessible_subnet_map()


def _is_admin():
    try:
        from jen.plugin_api import is_admin_or_above

        return is_admin_or_above()
    except Exception:
        role = getattr(current_user, "role", None)
        if role is not None:
            return role in ("superadmin", "admin")
        return bool(getattr(current_user, "is_admin", False))


def _require_write():
    if _is_admin():
        return True
    flash("Viewers can look at DNS Sync but not change it.", "error")
    return False


def _can(subnet_id):
    """The session user's subnet predicate — `plugin_api.can_access_subnet`, so
    `_can(None)` is True only for an unrestricted user (v5.65.2). Kept as one
    function so the tests and the pure helpers above take it as a parameter."""
    from jen.plugin_api import can_access_subnet

    return can_access_subnet(subnet_id)


def _all_subnets_user():
    return _can(None)


def _target_subnets(target):
    raw = target.get("subnet_ids") or "[]"
    try:
        return [int(v) for v in (json.loads(raw) if isinstance(raw, str) else raw)]
    except (TypeError, ValueError):
        return []


def _derive_subnet_id(ip, subnet_map):
    """Pure-in-spirit (no I/O) but kept near its only caller: the Kea
    subnet id whose CIDR contains `ip`, or None."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    for sid, info in subnet_map.items():
        try:
            if addr in ipaddress.IPv4Network(info["cidr"], strict=False):
                return sid
        except ValueError:
            continue
    return None


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"DNS Sync: audit failed: {e}")


# ── Source queries (impure DB reads, filtered to a target's own subnet scope) ──


def _in_placeholders(values):
    """A `%s,%s,...` clause sized to `values`, for a dynamic `IN (...)` —
    same helper shape as Jen's own add_subnet_restriction()."""
    return ",".join(["%s"] * len(values))


def _leases_for_subnets(subnet_ids):
    if not subnet_ids:
        return []
    db = None
    try:
        db = _get_kea_db()
        with db.cursor() as cur:
            cur.execute(
                f"SELECT inet_ntoa(address) AS ip, hostname, subnet_id FROM lease4 "  # nosec B608 - only `%s` placeholders are interpolated; every value is bound
                f"WHERE state=0 AND hostname IS NOT NULL AND hostname != '' "
                f"AND subnet_id IN ({_in_placeholders(subnet_ids)})",
                tuple(subnet_ids),
            )
            return cur.fetchall()
    except Exception as e:
        logger.warning(f"DNS Sync: lease source failed: {e}")
        return []
    finally:
        if db:
            db.close()


def _reservations_for_subnets(subnet_ids):
    if not subnet_ids:
        return []
    db = None
    try:
        db = _get_kea_db()
        with db.cursor() as cur:
            cur.execute(
                f"SELECT inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_subnet_id AS subnet_id FROM hosts "  # nosec B608 - only `%s` placeholders are interpolated; every value is bound
                f"WHERE ipv4_address IS NOT NULL AND ipv4_address > 0 AND hostname IS NOT NULL AND hostname != '' "
                f"AND dhcp4_subnet_id IN ({_in_placeholders(subnet_ids)})",
                tuple(subnet_ids),
            )
            return cur.fetchall()
    except Exception as e:
        logger.warning(f"DNS Sync: reservation source failed: {e}")
        return []
    finally:
        if db:
            db.close()


def _ipam_for_subnets(subnet_ids):
    if not subnet_ids:
        return []
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                f"SELECT ip, label AS hostname, subnet_id FROM ipam_static_entries "  # nosec B608 - only `%s` placeholders are interpolated; every value is bound
                f"WHERE subnet_kind='kea' AND entry_status IN ('static','planned') "
                f"AND label IS NOT NULL AND label != '' AND subnet_id IN ({_in_placeholders(subnet_ids)})",
                tuple(subnet_ids),
            )
            return cur.fetchall()
    except Exception:
        return []  # IPAM Lite not installed, or its table not yet migrated
    finally:
        if db:
            db.close()


def _desired_for_target(target):
    """(desired `{name: ip}`, source_by_name `{name: source}`, skipped)."""
    subnet_ids = json.loads(target.get("subnet_ids") or "[]")
    sources = set((target.get("sources") or "").split(",")) & set(_SOURCES)
    raw = build_desired(
        sources,
        _leases_for_subnets(subnet_ids),
        _reservations_for_subnets(subnet_ids),
        _ipam_for_subnets(subnet_ids),
    )
    desired_with_source, skipped = normalize_desired(raw)
    desired = {name: ip for name, (ip, _source) in desired_with_source.items()}
    source_by_name = {name: source for name, (_ip, source) in desired_with_source.items()}
    return desired, source_by_name, skipped


# ── Ledger (ds_records) ─────────────────────────────────────────────────────────


def _ledger_for_target(target_id):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT name, ip, source FROM ds_records WHERE target_id=%s", (target_id,))
            rows = cur.fetchall()
    finally:
        if db:
            db.close()
    return {r["name"]: r["ip"] for r in rows}, rows


# ── Remote clients (impure: urllib only, TLS verified by default) ──────────────


def _ssl_context(url, allow_self_signed):
    if not url.startswith("https://"):
        return None
    ctx = ssl.create_default_context()
    if allow_self_signed:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_call(method, url, headers=None, body=None, allow_self_signed=False):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S, context=_ssl_context(url, allow_self_signed)) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        status = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise _SyncError(str(e)[:200]) from e
    parsed = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
    return status, parsed


def _pihole_sid(target):
    password = ""
    if target.get("credential"):
        from jen.plugin_api import decrypt_secret

        password = decrypt_secret(target["credential"])
    _status, parsed = _http_call(
        "POST",
        f"{target['url']}/api/auth",
        body={"password": password},
        allow_self_signed=bool(target.get("allow_self_signed")),
    )
    session = (parsed or {}).get("session") or {}
    if not session.get("valid"):
        raise _SyncError(session.get("message") or "Pi-hole authentication failed")
    return session.get("sid")


def _pihole_logout(target, sid):
    """Best effort: end the session this sync opened (`DELETE /api/auth`). A
    failure is only logged — the session expires by itself in 30 minutes."""
    if not sid:
        return
    try:
        _http_call(
            "DELETE",
            f"{target['url']}/api/auth",
            headers={"X-FTL-SID": sid},
            allow_self_signed=bool(target.get("allow_self_signed")),
        )
    except _SyncError as e:
        logger.debug(f"DNS Sync: Pi-hole logout failed: {e}")


@contextlib.contextmanager
def _remote_session(target):
    """One authenticated session per sync or preview: yields the Pi-hole `sid`
    (None for AdGuard Home, whose auth is per-request Basic, and for a Pi-hole
    with no password set) and logs it out on the way out. Before 1.0.2 every
    `_pihole_fetch_remote` opened its own and nothing ever closed one — Pi-hole
    caps concurrent sessions, so a busy target could lock the operator out of
    their own web interface."""
    sid = _pihole_sid(target) if target["kind"] == "pihole" else None
    try:
        yield sid
    finally:
        if target["kind"] == "pihole":
            _pihole_logout(target, sid)


def _pihole_fetch_remote(target, sid):
    headers = {"X-FTL-SID": sid} if sid else {}
    status, parsed = _http_call(
        "GET",
        f"{target['url']}/api/config/dns/hosts",
        headers=headers,
        allow_self_signed=bool(target.get("allow_self_signed")),
    )
    if status != 200:
        raise _SyncError(f"Pi-hole GET hosts failed (HTTP {status})")
    lines = (((parsed or {}).get("config") or {}).get("dns") or {}).get("hosts") or []
    out = {}
    for line in lines:
        parsed_line = parse_pihole_hosts_line(line)
        if parsed_line:
            ip, name = parsed_line
            out[name] = ip
    return out


def _pihole_apply(target, sid, method, ip, name):
    headers = {"X-FTL-SID": sid} if sid else {}
    path = pihole_hosts_value_path(ip, name)
    status, _parsed = _http_call(
        method,
        f"{target['url']}/api/config/dns/hosts/{path}",
        headers=headers,
        allow_self_signed=bool(target.get("allow_self_signed")),
    )
    ok_statuses = (201,) if method == "PUT" else (204,)
    if status not in ok_statuses and not (method == "DELETE" and status == 404):
        raise _SyncError(f"Pi-hole {method} hosts/{name} failed (HTTP {status})")


def _adguard_auth_header(target):
    credential = ""
    if target.get("credential"):
        from jen.plugin_api import decrypt_secret

        credential = decrypt_secret(target["credential"])
    import base64

    token = base64.b64encode(credential.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _adguard_fetch_remote(target):
    headers = _adguard_auth_header(target)
    status, parsed = _http_call(
        "GET",
        f"{target['url']}/control/rewrite/list",
        headers=headers,
        allow_self_signed=bool(target.get("allow_self_signed")),
    )
    if status != 200:
        raise _SyncError(f"AdGuard Home GET rewrite/list failed (HTTP {status})")
    suffix = f".{target['domain']}"
    out = {}
    for entry in parsed or []:
        domain = str(entry.get("domain", ""))
        if domain.endswith(suffix):
            out[domain[: -len(suffix)]] = entry.get("answer", "")
    return out


def _adguard_apply(target, action, ip, name):
    headers = _adguard_auth_header(target)
    body = {"domain": adguard_fqdn(name, target["domain"]), "answer": ip}
    path = "add" if action == "add" else "delete"
    status, _parsed = _http_call(
        "POST",
        f"{target['url']}/control/rewrite/{path}",
        headers=headers,
        body=body,
        allow_self_signed=bool(target.get("allow_self_signed")),
    )
    if status != 200:
        raise _SyncError(f"AdGuard Home {action} {name} failed (HTTP {status})")


def _fetch_remote(target, sid=None):
    if target["kind"] == "pihole":
        return _pihole_fetch_remote(target, sid)
    return _adguard_fetch_remote(target)


def _apply_add(target, sid, name, ip):
    if target["kind"] == "pihole":
        _pihole_apply(target, sid, "PUT", ip, name)
    else:
        _adguard_apply(target, "add", ip, name)


def _apply_remove(target, sid, name, ip):
    if target["kind"] == "pihole":
        _pihole_apply(target, sid, "DELETE", ip, name)
    else:
        _adguard_apply(target, "remove", ip, name)


# ── Sync orchestration (impure: DB + network; the pure planner does the thinking) ──


def _plan_for_target(target, sid=None, session_error=None):
    """(plan, desired, source_by_name, ledger, skipped, remote_error).
    Fetches the remote list once, on the caller's session. A fetch failure
    still returns a plan (add-only, `remote` degrades to {}) so PREVIEW can show
    the operator something and say why; a real sync must not act on it —
    `_sync_one_target` aborts when `remote_error` is set."""
    desired, source_by_name, skipped = _desired_for_target(target)
    ledger, _rows = _ledger_for_target(target["id"])
    remote, remote_error = {}, session_error
    if session_error is None:
        try:
            remote = _fetch_remote(target, sid)
        except _SyncError as e:
            remote_error = str(e)
    plan = plan_sync(desired, ledger, remote)
    return plan, desired, source_by_name, ledger, skipped, remote_error


# One lock per target: the debounced sync and the 15-minute reconcile both call
# `_sync_one_target`, and two runs against one target would each plan from the
# same ledger and then apply overlapping changes.
_target_locks: dict[int, threading.Lock] = {}
_target_locks_guard = threading.Lock()


def _lock_for(target_id):
    with _target_locks_guard:
        return _target_locks.setdefault(target_id, threading.Lock())


def _sync_one_target(target_id):
    lock = _lock_for(target_id)
    if not lock.acquire(blocking=False):
        logger.info(f"DNS Sync: target {target_id} is already syncing; skipping this run")
        return
    try:
        _sync_locked(target_id)
    finally:
        lock.release()


def _sync_locked(target_id):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM ds_targets WHERE id=%s", (target_id,))
            target = cur.fetchone()
    finally:
        if db:
            db.close()
    if not target or not target["enabled"] or not target["previewed_at"]:
        return

    try:
        with _remote_session(target) as sid:
            plan, _desired, source_by_name, ledger, _skipped, remote_error = _plan_for_target(target, sid)
            if remote_error:
                # The remote list is what tells a drifted record from a missing one; without it
                # every record would still cost its own 10 s call. Stop and say so.
                _record_sync_result(target_id, remote_error)
                _maybe_alert(target, remote_error)
                return
            upserts, removes, errors = apply_plan(
                plan,
                ledger,
                source_by_name,
                lambda name, ip: _apply_add(target, sid, name, ip),
                lambda name, ip: _apply_remove(target, sid, name, ip),
            )
    except _SyncError as e:
        _record_sync_result(target_id, str(e))
        _maybe_alert(target, str(e))
        return

    _update_ledger(target_id, upserts, removes)

    _record_sync_result(target_id, "; ".join(errors[:5]))
    if errors:
        _maybe_alert(target, "; ".join(errors[:3]))


def _update_ledger(target_id, applied_upsert, applied_remove):
    """`applied_upsert`: [(name, ip, source)] that the remote call
    genuinely succeeded for; `applied_remove`: [name] likewise. Only
    ever reflects what was actually delivered — a failed API call
    leaves the ledger untouched so the next sync retries it."""
    if not (applied_upsert or applied_remove):
        return
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            # removals first: an UPDATE is a removal of the old record followed by an add of the
            # new one, so the same name is in both lists and the row must end up holding the new IP
            for name in applied_remove:
                cur.execute("DELETE FROM ds_records WHERE target_id=%s AND name=%s", (target_id, name))
            for name, ip, source in applied_upsert:
                cur.execute(
                    "INSERT INTO ds_records (target_id, name, ip, source) VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE ip=VALUES(ip), source=VALUES(source)",
                    (target_id, name, ip, source),
                )
        db.commit()
    except Exception as e:
        logger.error(f"DNS Sync: ledger update failed: {e}")
    finally:
        if db:
            db.close()


def _record_sync_result(target_id, error_summary):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE ds_targets SET last_sync_at=UTC_TIMESTAMP(), last_error=%s WHERE id=%s",
                (error_summary[:300], target_id),
            )
        db.commit()
    except Exception as e:
        logger.error(f"DNS Sync: recording sync result failed: {e}")
    finally:
        if db:
            db.close()


def _maybe_alert(target, error_summary):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    last = target.get("last_alert_at")
    if last is not None and (now - last).total_seconds() < _ALERT_COOLDOWN_S:
        return
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE ds_targets SET last_alert_at=UTC_TIMESTAMP() WHERE id=%s", (target["id"],))
        db.commit()
    except Exception as e:
        logger.error(f"DNS Sync: could not stamp last_alert_at: {e}")
    finally:
        if db:
            db.close()
    try:
        from jen.plugin_api import send_alert

        send_alert("dns-sync_failed", subnet_id=None, name=target["name"], kind=target["kind"], error=error_summary)
    except Exception as e:
        logger.warning(f"DNS Sync: could not send dns-sync_failed alert: {e}")


# ── Debounce glue (impure: threading.Timer, driven by the pure state above) ────

_debounce_lock = threading.Lock()
_debounce_pending: dict[int, datetime] = {}
_debounce_timers: dict[int, threading.Timer] = {}


def _touch_target(target_id):
    now = datetime.now(timezone.utc)
    with _debounce_lock:
        global _debounce_pending
        _debounce_pending = debounce_schedule(_debounce_pending, target_id, now)
        old = _debounce_timers.get(target_id)
        if old is not None:
            old.cancel()
        t = threading.Timer(_DEBOUNCE_DELAY_S, _fire_debounced_sync, args=(target_id,))
        t.daemon = True
        _debounce_timers[target_id] = t
        t.start()


def _fire_debounced_sync(target_id):
    with _debounce_lock:
        global _debounce_pending
        _, _debounce_pending = debounce_ready(_debounce_pending, datetime.now(timezone.utc))
        _debounce_timers.pop(target_id, None)
    try:
        _sync_one_target(target_id)
    except Exception as e:
        logger.error(f"DNS Sync: debounced sync of target {target_id} failed: {e}")


def _targets_touched_by_event(event):
    subnet_id = event.get("subnet_id")
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, subnet_ids FROM ds_targets WHERE enabled=1")
            rows = cur.fetchall()
    except Exception:
        return []
    finally:
        if db:
            db.close()
    if subnet_id is None:
        return [r["id"] for r in rows]
    out = []
    for r in rows:
        if subnet_id in json.loads(r["subnet_ids"] or "[]"):
            out.append(r["id"])
    return out


def _on_relevant_event(event):
    for target_id in _targets_touched_by_event(event):
        _touch_target(target_id)


def _reconcile_tick():
    """The 15-minute periodic job: a full sync of every enabled,
    previewed target, independent of any event — catches anything a
    debounced event-driven sync missed (a restart mid-burst, a target
    enabled between events, drift from a manual remote edit)."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id FROM ds_targets WHERE enabled=1 AND previewed_at IS NOT NULL")
            ids = [r["id"] for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"DNS Sync: reconcile tick could not list targets: {e}")
        return
    finally:
        if db:
            db.close()
    for target_id in ids:
        try:
            _sync_one_target(target_id)
        except Exception as e:
            logger.error(f"DNS Sync: reconcile of target {target_id} failed: {e}")


# ── Routes: page ────────────────────────────────────────────────────────────


def _target_rows():
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, kind, url, domain, sources, subnet_ids, allow_self_signed, enabled, "
                "previewed_at, last_sync_at, last_error, created_by FROM ds_targets ORDER BY name"
            )
            rows = cur.fetchall()
    except Exception as e:
        logger.error(f"DNS Sync: index error: {e}")
        rows = []
    finally:
        if db:
            db.close()
    return rows


def _load_target(target_id):
    """The whole ds_targets row, or None."""
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM ds_targets WHERE id=%s", (target_id,))
            return cur.fetchone()
    finally:
        if db:
            db.close()


def _visible_records(target_id):
    """The ledger rows of a target that the session user may see. A record's subnet is where
    its IP actually lives; one that lives in no known subnet belongs to unrestricted users only."""
    subnet_map = _subnet_map()
    _ledger, rows = _ledger_for_target(target_id)
    return [r for r in rows if _can(_derive_subnet_id(r["ip"], subnet_map))]


def _reachable_target(target_id):
    """The target when the caller may see it at all, else None — the same answer for a
    target that does not exist and one in subnets the caller has no access to."""
    target = _load_target(target_id)
    if target is None or not target_visible(_target_subnets(target), _can):
        return None
    return target


@bp.route("/")
@login_required
def index():
    rows = []
    for r in _target_rows():
        ids = _target_subnets(r)
        if not target_visible(ids, _can):
            continue
        r["can_manage"] = target_manageable(ids, _can)
        r["record_count"] = len(_visible_records(r["id"]))
        rows.append(r)
    accessible = _accessible_subnets()
    subnet_map = _subnet_map()
    accessible_subnets = [
        {"id": sid, "name": subnet_map.get(sid, {}).get("name") or f"subnet {sid}"} for sid in sorted(accessible)
    ]
    admin = _is_admin()
    return render_template(
        "dns_sync/index.html",
        rows=rows,
        kinds=_KINDS,
        sources=_SOURCES,
        accessible_subnets=accessible_subnets,
        is_admin=admin,
        can_create=admin and _all_subnets_user(),
    )


@bp.route("/targets/add", methods=["POST"])
@login_required
def add_target():
    if not _require_write():
        return redirect(url_for("dns_sync.index"))
    if not _all_subnets_user():
        # A target holds the DNS server's credential and applies to a whole set of subnets, so it is
        # global integration configuration: only an account that can see every subnet may create one.
        flash("Adding a DNS Sync target needs an account that can see every subnet.", "error")
        return redirect(url_for("dns_sync.index"))

    name = request.form.get("name", "").strip()[:100]
    kind = request.form.get("kind", "")
    if kind not in _KINDS:
        flash("Pick a supported DNS server type.", "error")
        return redirect(url_for("dns_sync.index"))
    url = request.form.get("url", "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        flash("URL must start with http:// or https://.", "error")
        return redirect(url_for("dns_sync.index"))
    domain, domain_error = normalize_domain(request.form.get("domain", "lan"))
    if domain is None:
        flash(domain_error, "error")
        return redirect(url_for("dns_sync.index"))
    selected_sources = set(request.form.getlist("sources")) & set(_SOURCES)
    if not selected_sources:
        flash("Pick at least one source.", "error")
        return redirect(url_for("dns_sync.index"))
    allow_self_signed = 1 if request.form.get("allow_self_signed") else 0
    credential_raw = request.form.get("credential", "")

    accessible = list(_accessible_subnets())
    scope_all = request.form.get("scope_all") == "on"
    if scope_all:
        subnet_ids = resolve_subnet_ids(None, accessible)
    else:
        try:
            selected_ids = [int(v) for v in request.form.getlist("subnet_ids")]
        except ValueError:
            selected_ids = []
        subnet_ids = resolve_subnet_ids(selected_ids, accessible)

    credential = ""
    if credential_raw:
        from jen.plugin_api import encrypt_secret

        credential = encrypt_secret(credential_raw)

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO ds_targets (name, kind, url, credential, domain, sources, subnet_ids, "
                "allow_self_signed, enabled, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, %s)",
                (
                    name,
                    kind,
                    url,
                    credential,
                    domain,
                    ",".join(sorted(selected_sources)),
                    json.dumps(subnet_ids),
                    allow_self_signed,
                    current_user.username,
                ),
            )
        db.commit()
        flash(f"{name} added — run Preview before enabling it.", "success")
        _audit("DNSSYNC_ADD_TARGET", name, f"kind={kind} url={url}")
    except Exception as e:
        logger.error(f"DNS Sync: could not add target: {e}")
        flash("Could not add target; the details are in Jen's log.", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/preview", methods=["POST"])
@login_required
def preview_target(target_id):
    if not _require_write():
        return jsonify({"error": "forbidden"}), 403
    target = _reachable_target(target_id)
    if not target:
        return jsonify({"error": "not found"}), 404
    if not target_manageable(_target_subnets(target), _can):
        # Preview stamps `previewed_at`, which is what lets the target be enabled, so it is a write:
        # it needs the same every-subnet access enabling does.
        return jsonify({"error": "this target covers subnets you cannot access"}), 403

    try:
        with _remote_session(target) as sid:
            plan, _desired, _source_by_name, _ledger, skipped, remote_error = _plan_for_target(target, sid)
    except _SyncError as e:
        plan, _desired, _source_by_name, _ledger, skipped, remote_error = _plan_for_target(
            target, None, session_error=str(e)
        )

    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE ds_targets SET previewed_at=UTC_TIMESTAMP() WHERE id=%s", (target_id,))
        db.commit()
    except Exception as e:
        logger.error(f"DNS Sync: could not stamp previewed_at: {e}")
    finally:
        if db:
            db.close()

    return jsonify(
        {
            "add": plan["add"],
            "update": plan["update"],
            "remove": plan["remove"],
            "skipped": [{"ip": ip, "raw": raw, "reason": reason} for ip, raw, reason in skipped],
            "remote_error": remote_error,
        }
    )


@bp.route("/targets/<int:target_id>/toggle", methods=["POST"])
@login_required
def toggle_target(target_id):
    if not _require_write():
        return redirect(url_for("dns_sync.index"))
    row = _reachable_target(target_id)
    if row is None:
        flash("Target not found.", "error")
        return redirect(url_for("dns_sync.index"))
    if not target_manageable(_target_subnets(row), _can):
        flash("That target covers subnets you cannot access, so you cannot change it.", "error")
        return redirect(url_for("dns_sync.index"))
    if not row["enabled"] and not row["previewed_at"]:
        flash("Run Preview before enabling a target for the first time.", "error")
        return redirect(url_for("dns_sync.index"))
    new_enabled = 0 if row["enabled"] else 1
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE ds_targets SET enabled=%s WHERE id=%s", (new_enabled, target_id))
        db.commit()
        flash("Target enabled." if new_enabled else "Target paused.", "success")
        if new_enabled:
            _touch_target(target_id)
    except Exception as e:
        logger.error(f"DNS Sync: could not update target: {e}")
        flash("Could not update target; the details are in Jen's log.", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id):
    if not _require_write():
        return redirect(url_for("dns_sync.index"))
    if not _all_subnets_user():
        flash("Removing a DNS Sync target needs an account that can see every subnet.", "error")
        return redirect(url_for("dns_sync.index"))
    if _load_target(target_id) is None:
        flash("Target not found.", "error")
        return redirect(url_for("dns_sync.index"))
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM ds_records WHERE target_id=%s", (target_id,))
            cur.execute("DELETE FROM ds_targets WHERE id=%s", (target_id,))
        db.commit()
        flash("Target removed. Jen does not delete its records from the remote server automatically.", "success")
        _audit("DNSSYNC_DELETE_TARGET", str(target_id), "target removed")
    except Exception as e:
        logger.error(f"DNS Sync: could not remove target: {e}")
        flash("Could not remove target; the details are in Jen's log.", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/records")
@login_required
def target_records(target_id):
    if _reachable_target(target_id) is None:
        return jsonify({"error": "not found"}), 404
    rows = [{"name": r["name"], "ip": r["ip"], "source": r["source"]} for r in _visible_records(target_id)]
    return jsonify({"rows": rows})


@bp.route("/targets/<int:target_id>/export-unbound")
@login_required
def export_unbound(target_id):
    target = _reachable_target(target_id)
    if target is None:
        return Response("Target not found.", status=404, mimetype="text/plain")
    # The same per-record filter the record list applies: an export of the whole ledger would hand
    # a subnet-restricted user the names and addresses of hosts in subnets they cannot see.
    records = {r["name"]: r["ip"] for r in _visible_records(target_id)}
    body = unbound_export(records, target["domain"])
    return Response(
        body,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=dns-sync-{target_id}-unbound.conf"},
    )


def register(app):
    app.register_blueprint(bp)

    from jen.plugin_api import register_alert_type, register_periodic, subscribe

    register_alert_type(
        PLUGIN_ID,
        "dns-sync_failed",
        label="DNS Sync: sync failed",
        icon="triangle-alert",
        default_template="⚠️ DNS Sync target <b>{name}</b> ({kind}) failed: {error}",
    )

    for kind in _EVENT_KINDS:
        subscribe(kind, _on_relevant_event)

    register_periodic(PLUGIN_ID, "reconcile", _reconcile_tick, 15)

    logger.info("Local DNS Sync plugin registered")
