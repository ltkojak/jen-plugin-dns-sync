# Local DNS Sync — Jen Plugin

Pushes DHCP names — from active leases, Kea reservations, and [IPAM Lite](https://github.com/ltkojak/jen-plugin-ipam) entries — into [Pi-hole](https://pi-hole.net/) or [AdGuard Home](https://adguard.com/adguard-home/overview.html)'s local DNS, so a name like `nas.lan` resolves on the LAN without Kea DDNS, which assumes a BIND-style server most homelabs don't run.

> **IPv4 only.** DNS Sync tracks IPv4 addresses. This isn't a bug or a gap to report — it's a deliberate scope decision, the same one every other bundled plugin makes.

## Requirements

- [Jen](https://github.com/ltkojak/jen-kea) v5.65.2 or later
- A Pi-hole v6 install (the REST API introduced with `pihole-FTL` v6) or an AdGuard Home install with its `/control` API reachable from the Jen host

## Why a ledger, not a mirror

DNS Sync never treats the remote server's whole record set as something it owns. Every record it creates is written to its own ledger table, and every sync — the debounced event-driven one and the 15-minute reconcile — only ever proposes removing a name that's *in that ledger*. A record you (or anything else) added to Pi-hole or AdGuard by hand is never touched, even if DNS Sync's desired set changes underneath it and even though the remote server's own record list is fetched and compared on every sync (to catch drift, not to decide what's safe to delete).

## Who can do what

A target is an **all-known object**: it holds the DNS server's credential and pushes the names of every subnet it lists. Acting on it (Preview, Enable, Pause) needs access to *every* one of those subnets; creating and deleting a target is for accounts that can see every subnet; a target that lists no subnet is for those accounts alone. Only *seeing* is scoped: one accessible subnet is enough to see that a target exists, and its record list and Unbound export are filtered record by record by where each address lives. A target you cannot see is answered like one that does not exist. Viewers can look but never change anything.

## Mandatory preview

A target starts paused. The **Preview** button runs the full planner — normalise names, resolve collisions, diff against the ledger and the remote server — without applying anything, and shows exactly what would change. Only after a preview has run can a target be enabled; the Enable action refuses otherwise. This isn't a UI nudge — it's enforced by the same route that flips the target live.

## Features

- **Three sources**, any combination: active DHCP leases, Kea reservations, IPAM Lite static/planned entries. When more than one source names the same IP differently, a reservation wins over a lease, which wins over an IPAM Lite entry
- **Name normalisation**: lower-cased, `_` mapped to `-`, anything that still isn't a valid single DNS label is skipped (with a reason, shown in Preview) rather than silently mangled; a name collision between two different IPs gets a deterministic `-2`, `-3`, … suffix by ascending IP order
- **Event-driven, debounced sync**: a lease or reservation change fires a sync ~10 seconds after the last related event in a burst quiets down, so a DHCP renewal storm doesn't hammer the DNS server with one HTTP call per lease
- **15-minute full reconcile** independent of events, catching anything a debounced sync missed (a restart mid-burst, a target enabled between events, drift from a manual edit on the remote server)
- **Per-target scope**: pick specific Kea subnets or "all I can access" (resolved to an explicit list when you save, not re-derived from whoever happens to be logged in when a background sync runs)
- **TLS verified by default**, with a per-target "allow a self-signed certificate" switch for a Pi-hole or AdGuard install using one
- Credentials are stored encrypted and never rendered back — the form just shows a password field, blank, every time
- **Export "Unbound local-data"**: Unbound has no write API, so any target's current ledger can be downloaded as a ready-to-include `local-data:` snippet instead

## Installation

Open Jen → **Settings → Plugins** and click **Install** next to Local DNS Sync. Jen downloads the release pinned in its plugin registry, verifies its checksum, and enables it; restart Jen when prompted.

To install by hand instead (a checkout without registry access), unzip `plugin.zip` from the release tag you want into `/var/lib/jen/plugins/dns-sync/`, then enable it from Settings → Plugins and restart Jen.

## Development

`python3 tools/verify.py --build` rebuilds `plugin.zip` deterministically from the tree and runs the same checks CI runs on every push and tag: the zip matches the tree byte-for-byte, no template carries an inline event handler, an inline `style=` attribute, an un-nonce'd `<script>`, or a POST form missing `csrf_token` (Jen's CSP and CSRF protection would silently break the first, third and fourth), `manifest.json`'s version matches the top `CHANGELOG.md` entry, and `plugin.py` compiles and passes ruff. The committed `plugin.zip` is the artifact Jen installs, so rebuild it in the same commit as any change.

`python3 tools/test_plugin.py` exercises every pure function — name normalisation, the collision-suffixing dedupe, the source-priority merge, the planner (including the foreign-record invariant), the Pi-hole hosts-line parser, the Unbound export, and the debounce state machine — plus the applier (an IP change leaves exactly one record), the Pi-hole session, the per-target lock and every by-id route's authorization, against hand-built inputs and fakes, no Jen, database, or network access needed.

## API references

Every request shape this plugin sends is quoted in `plugin.py`'s own module docstring, pinned to the vendor's OpenAPI source (not a blog post) with the date it was read:

- Pi-hole v6: [`pi-hole/FTL`](https://github.com/pi-hole/FTL), `src/api/docs/content/specs/{auth,config}.yaml`
- AdGuard Home: [`AdguardTeam/AdGuardHome`](https://github.com/AdguardTeam/AdGuardHome), `openapi/openapi.yaml`

## Version History

See [CHANGELOG.md](CHANGELOG.md).

## License

GPL v3 — Copyright 2026 Matthew Thibodeau
