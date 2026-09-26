# Local DNS Sync Plugin — Changelog

## [1.0.3] - 2026-09-26

Requires Jen 5.65.2 or later, like 1.0.2.

### Fixed: database error text reached the page

A failed save put the database's own error message into the page, which can carry a table or column name, a user name or a host address. The details are now written to Jen's log and the page shows a generic message. Jen's test suite now scans every bundled plugin for this and fails on a new one; messages about the outside world this plugin was configured to talk to (a Pi-hole or AdGuard Home's own refusal or connection error, shown on the target) are the deliberate exception, because that text is the diagnostic an operator needs.

### Changed

- `tools/test_plugin.py` runs a failing database through the add route and requires a generic message with no exception text.

## [1.0.2] - 2026-09-25

Requires Jen 5.65.2 or later (the `can_access_subnet` helper in the plugin API).

### Fixed: an IP change left the old record answering

Changing a host's address planned an "update", and the applier handled an
update by adding the new record only. Pi-hole keeps every `"ip name"` line
it is given and AdGuard Home keeps every rewrite, so both servers ended up
with the old and the new address for the same name — and because the
ledger by then held the new address, nothing could ever clean the old one
up. An update is now what the module documentation always said it was: the
record the ledger holds is removed, then the new one is added. If the
removal fails the add is not attempted (the remote is unchanged and the
ledger still says so); if the removal worked and the add failed, the ledger
row is dropped so the next run is a plain add. A record Jen did not create is
still never touched.

### Fixed: routes authorised one thing and acted on another

A subnet-restricted user could preview, enable, pause or delete a target by
its id, and download its whole ledger as an Unbound file, whatever subnets
the target covered. Preview mattered most: it returned the names and
addresses of hosts in subnets the caller could not see, and stamped the
timestamp that lets a target be enabled. The bug shape this release names in every plugin: the route checked one thing (nothing, for a by-id
POST) and acted on another (a target that pushes subnets the caller has no
access to).

A DNS Sync target is now treated as an all-known object. Acting on it
(preview, enable, pause) needs access to **every** subnet it covers;
creating and deleting one — it holds the DNS server's credential and applies
to a set of subnets — is for accounts that can see every subnet; a target
that lists no subnet is likewise for those accounts alone. Only *seeing* a
target and its records stays scoped: one accessible subnet is enough to see
that a target exists, and the record list and the Unbound export are filtered
record by record, by where each address actually lives (an address in no known
subnet is for unrestricted accounts only). A target you cannot see is
answered exactly as one that does not exist. The page hides the buttons a
caller could not use.

### Fixed: a failed fetch of the remote list did not stop the sync

When reading the DNS server's current records failed, the sync carried on
with an empty picture and made one 10-second call per record, each of them
failing the same way. It now stops at the first failure, records the error
on the target and raises the usual alert. Preview still shows what it can
and says why the remote list was unavailable.

### Fixed: Pi-hole sessions were never closed

Every read of a Pi-hole opened a fresh session and nothing ever closed one;
Pi-hole caps concurrent sessions, so a busy target could lock the operator
out of their own web interface until the sessions timed out. A sync or a
preview now opens one session, uses it for every call and ends it with
`DELETE /api/auth`.

### Fixed: two syncs of one target could overlap

The debounced, event-driven sync and the 15-minute reconcile both plan from the
ledger, so two runs at once could apply overlapping changes. A run now takes a
per-target lock and skips itself when the target is already syncing.

### Fixed: the domain suffix was cut, not checked

The suffix was truncated to 63 characters and stored as typed, so a value like
`a..b` or one with a space went straight into every record name and AdGuard
rewrite. It must now be dot-separated DNS labels that fit the column, or the
target is not saved.

### Changed

- The CSRF token in the page's script is emitted with `|tojson`, not pasted
  between quotes.
- The page's static styling moved out of inline `style=` attributes into the
  page's own `<style>` block; `tools/verify.py` now fails a template that
  carries one.
- The three dynamic `IN (...)` builders carry a one-line `# nosec B608` saying
  why they are safe (only `%s` placeholders are interpolated).
- `tools/test_plugin.py` calls the real applier, session, lock and route
  functions against fakes: an IP change ends with exactly one record on the
  remote, a failed fetch makes no per-record call, a restricted caller is
  refused on every by-id route.

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
