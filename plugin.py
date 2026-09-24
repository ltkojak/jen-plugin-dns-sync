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

**Mandatory preview.** A target is created `enabled=0`. The Preview
action runs the planner without applying anything and stamps
`previewed_at`; the Enable toggle refuses (flash, no state change) when
`previewed_at IS NULL` — a target genuinely cannot go live without an
operator having seen what it would do first.
"""

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


def _all_subnets_user():
    return bool(getattr(current_user, "all_subnets", False))


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


def _target_visible(target_subnet_ids, accessible, all_subnets):
    if all_subnets:
        return True
    if not target_subnet_ids:
        return False
    return bool(set(target_subnet_ids) & set(accessible))


def _audit(action, target, detail):
    try:
        from jen.plugin_api import audit

        audit(action, target, detail)
    except Exception as e:
        logger.error(f"DNS Sync: audit failed: {e}")


# ── Source queries (impure DB reads, filtered to a target's own subnet scope) ──


def _leases_for_subnets(subnet_ids):
    if not subnet_ids:
        return []
    db = None
    try:
        db = _get_kea_db()
        with db.cursor() as cur:
            placeholders = ",".join(["%s"] * len(subnet_ids))
            cur.execute(
                f"SELECT inet_ntoa(address) AS ip, hostname, subnet_id FROM lease4 "
                f"WHERE state=0 AND hostname IS NOT NULL AND hostname != '' AND subnet_id IN ({placeholders})",
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
            placeholders = ",".join(["%s"] * len(subnet_ids))
            cur.execute(
                f"SELECT inet_ntoa(ipv4_address) AS ip, hostname, dhcp4_subnet_id AS subnet_id FROM hosts "
                f"WHERE ipv4_address IS NOT NULL AND ipv4_address > 0 AND hostname IS NOT NULL AND hostname != '' "
                f"AND dhcp4_subnet_id IN ({placeholders})",
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
            placeholders = ",".join(["%s"] * len(subnet_ids))
            cur.execute(
                f"SELECT ip, label AS hostname, subnet_id FROM ipam_static_entries "
                f"WHERE subnet_kind='kea' AND entry_status IN ('static','planned') "
                f"AND label IS NOT NULL AND label != '' AND subnet_id IN ({placeholders})",
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


def _pihole_fetch_remote(target):
    sid = _pihole_sid(target)
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


def _fetch_remote(target):
    if target["kind"] == "pihole":
        return _pihole_fetch_remote(target)
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


def _plan_for_target(target):
    """(plan, desired, source_by_name, ledger, skipped, remote_error).
    Fetches the remote list best-effort — a remote fetch failure still
    returns a plan (add-only, since `remote` degrades to {}), so
    Preview and a real sync degrade the same way rather than blocking
    entirely."""
    desired, source_by_name, skipped = _desired_for_target(target)
    ledger, _rows = _ledger_for_target(target["id"])
    remote, remote_error = {}, None
    try:
        remote = _fetch_remote(target)
    except _SyncError as e:
        remote_error = str(e)
    plan = plan_sync(desired, ledger, remote)
    return plan, desired, source_by_name, ledger, skipped, remote_error


def _sync_one_target(target_id):
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

    plan, _desired, source_by_name, ledger, _skipped, remote_error = _plan_for_target(target)
    sid = None
    errors = []
    if target["kind"] == "pihole" and (plan["add"] or plan["update"] or plan["remove"]):
        try:
            sid = _pihole_sid(target)
        except _SyncError as e:
            errors.append(str(e))

    applied_upsert = []
    applied_remove = []
    if not errors:
        for name, ip in plan["add"] + plan["update"]:
            try:
                _apply_add(target, sid, name, ip)
                applied_upsert.append((name, ip, source_by_name.get(name, "lease")))
            except _SyncError as e:
                errors.append(f"{name}: {e}")
        for name in plan["remove"]:
            old_ip = ledger.get(name)
            try:
                _apply_remove(target, sid, name, old_ip)
                applied_remove.append(name)
            except _SyncError as e:
                errors.append(f"{name}: {e}")

    _update_ledger(target_id, applied_upsert, applied_remove)

    summary = "; ".join(errors[:5]) if errors else (remote_error or "")
    _record_sync_result(target_id, summary)
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
            for name, ip, source in applied_upsert:
                cur.execute(
                    "INSERT INTO ds_records (target_id, name, ip, source) VALUES (%s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE ip=VALUES(ip), source=VALUES(source)",
                    (target_id, name, ip, source),
                )
            for name in applied_remove:
                cur.execute("DELETE FROM ds_records WHERE target_id=%s AND name=%s", (target_id, name))
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

        send_alert("dns_sync_failed", subnet_id=None, name=target["name"], kind=target["kind"], error=error_summary)
    except Exception as e:
        logger.warning(f"DNS Sync: could not send dns_sync_failed alert: {e}")


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
            for r in rows:
                cur.execute("SELECT COUNT(*) AS n FROM ds_records WHERE target_id=%s", (r["id"],))
                r["record_count"] = cur.fetchone()["n"]
    except Exception as e:
        logger.error(f"DNS Sync: index error: {e}")
        rows = []
    finally:
        if db:
            db.close()
    return rows


@bp.route("/")
@login_required
def index():
    accessible = _accessible_subnets()
    all_subnets = _all_subnets_user()
    rows = [r for r in _target_rows() if _target_visible(json.loads(r["subnet_ids"] or "[]"), accessible, all_subnets)]
    subnet_map = _subnet_map()
    accessible_subnets = [
        {"id": sid, "name": subnet_map.get(sid, {}).get("name") or f"subnet {sid}"} for sid in sorted(accessible)
    ]
    return render_template(
        "dns_sync/index.html",
        rows=rows,
        kinds=_KINDS,
        sources=_SOURCES,
        accessible_subnets=accessible_subnets,
        is_admin=_is_admin(),
    )


@bp.route("/targets/add", methods=["POST"])
@login_required
def add_target():
    if not _require_write():
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
    domain = request.form.get("domain", "lan").strip().lower()[:63] or "lan"
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
        flash(f"Could not add target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/preview", methods=["POST"])
@login_required
def preview_target(target_id):
    if not _require_write():
        return jsonify({"error": "forbidden"}), 403
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM ds_targets WHERE id=%s", (target_id,))
            target = cur.fetchone()
    finally:
        if db:
            db.close()
    if not target:
        return jsonify({"error": "not found"}), 404

    plan, _desired, _source_by_name, _ledger, skipped, remote_error = _plan_for_target(target)

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
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT enabled, previewed_at FROM ds_targets WHERE id=%s", (target_id,))
            row = cur.fetchone()
            if row is None:
                flash("Target not found.", "error")
                return redirect(url_for("dns_sync.index"))
            if not row["enabled"] and not row["previewed_at"]:
                flash("Run Preview before enabling a target for the first time.", "error")
                return redirect(url_for("dns_sync.index"))
            new_enabled = 0 if row["enabled"] else 1
            cur.execute("UPDATE ds_targets SET enabled=%s WHERE id=%s", (new_enabled, target_id))
        db.commit()
        flash("Target enabled." if new_enabled else "Target paused.", "success")
        if new_enabled:
            _touch_target(target_id)
    except Exception as e:
        flash(f"Could not update target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id):
    if not _require_write():
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
        flash(f"Could not remove target: {e}", "error")
    finally:
        if db:
            db.close()
    return redirect(url_for("dns_sync.index"))


@bp.route("/targets/<int:target_id>/records")
@login_required
def target_records(target_id):
    accessible = _accessible_subnets()
    all_subnets = _all_subnets_user()
    subnet_map = _subnet_map()
    _ledger, rows = _ledger_for_target(target_id)
    out = []
    for r in rows:
        sid = _derive_subnet_id(r["ip"], subnet_map)
        if sid is not None and sid not in accessible and not all_subnets:
            continue
        if sid is None and not all_subnets:
            continue
        out.append({"name": r["name"], "ip": r["ip"], "source": r["source"]})
    return jsonify({"rows": out})


@bp.route("/targets/<int:target_id>/export-unbound")
@login_required
def export_unbound(target_id):
    db = None
    try:
        db = _get_db()
        with db.cursor() as cur:
            cur.execute("SELECT domain FROM ds_targets WHERE id=%s", (target_id,))
            target = cur.fetchone()
    finally:
        if db:
            db.close()
    if not target:
        flash("Target not found.", "error")
        return redirect(url_for("dns_sync.index"))
    ledger, _rows = _ledger_for_target(target_id)
    body = unbound_export(ledger, target["domain"])
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
        "dns_sync_failed",
        label="DNS Sync: sync failed",
        icon="triangle-alert",
        default_template="⚠️ DNS Sync target <b>{name}</b> ({kind}) failed: {error}",
    )

    for kind in _EVENT_KINDS:
        subscribe(kind, _on_relevant_event)

    register_periodic(PLUGIN_ID, "reconcile", _reconcile_tick, 15)

    logger.info("Local DNS Sync plugin registered")
