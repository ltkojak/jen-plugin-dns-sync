# Local DNS Sync Plugin — Changelog

## [1.0.1] - 2026-09-24

### Fixed: the plugin could not load on any Jen install

1.0.0's own alert type was registered as `dns_sync_failed` — an
all-underscore name — but Jen requires a plugin's alert type id to
start with the plugin's own id followed by an underscore, and this
plugin's id is `dns-sync`, with a hyphen. `dns_sync_failed` doesn't
start with `dns-sync_`, so `register_alert_type` raised on every
single start, Jen's per-plugin error handling caught it and moved on,
and Local DNS Sync never loaded: no nav item, no routes, no sync,
ever, on any install. The alert type is now `dns-sync_failed`,
matching the plugin's actual id; nothing else about it changes.

`tools/test_plugin.py` now calls `register(app)` end to end against a
stub that enforces the same id-prefix rule Jen's real
`register_alert_type` does, so a mismatch like this is caught before
it ever reaches a commit.

## [1.0.0] - 2026-09-24

### First release

Kea's DDNS integration assumes a BIND-style server; most homelabs run
Pi-hole, AdGuard Home, or Unbound instead. Local DNS Sync pushes DHCP
names — from active leases, Kea reservations, and IPAM Lite entries —
into a Pi-hole or AdGuard Home target so a name like `nas.lan` resolves
on the LAN without touching Kea's own DDNS configuration at all.
Unbound has no write API, so a target-less "Export Unbound local-data"
download covers it instead.

Every record this plugin creates is tracked in its own ledger, and a
sync only ever proposes removing a name that's in that ledger — a
record you added to the DNS server by hand, or anything else did, is
never touched, no matter what the remote server's own record list
looks like when it's fetched for drift comparison. A target starts
paused and stays that way until an operator runs Preview, which shows
the exact adds, updates, and removes a real sync would make without
applying any of them; only then can it be enabled.

Sync itself is event-driven: a lease or reservation change debounces
into one sync roughly ten seconds after the last related event in a
burst, so a DHCP renewal storm doesn't turn into one HTTP call per
lease. A full reconcile runs every fifteen minutes regardless, to
catch anything a debounced sync missed. Names are normalised to valid
DNS labels (lower-cased, underscores mapped to hyphens) and a
collision between two different addresses gets a deterministic
suffix rather than overwriting either one. Credentials are stored
encrypted and are never shown again once saved.

Built on Jen 5.57.0's plugin API v3 from the first commit: sprite
icons, a phone-ready rowlist, and no inline styles.
