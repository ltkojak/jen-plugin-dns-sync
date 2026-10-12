# Local DNS Sync Plugin — Changelog

## [1.1.3] - 2026-10-12

Fix and tidy-up from a whole-tree review of Jen's bundled plugins. `requires_jen` stays 5.68.0 (everything this release imports from `jen.plugin_api` is in 5.68.0 and earlier).

### Fixed: a target's URL cannot carry a password

A URL of the form `http://user:pass@pi.hole` was accepted and stored as typed, so the DNS server's password sat in the plain-text URL column, was printed on the page next to the target's name, and was copied into the audit log's description of the add. The credential has its own field, which is stored encrypted and never shown. Adding a target whose URL has a username or password in it is now refused with one sentence that says where the credential goes; the sentence echoes neither the URL nor the password. A target saved by an earlier version with one in its URL is shown without it (host, port, path and query are kept). The stored value itself is only cleared by removing the target and adding it again, which this release does not do on the operator's behalf.

### Fixed: a database error while loading a target or its ledger was a 500

`_load_target` (behind toggle, delete, Preview, the record list and the Unbound export) and `_ledger_for_target` (behind Preview, the record list, the export and every sync's plan) had no `except`, so a database failure surfaced as an error page, and a failure inside a sync died mid-plan. Both now log the failure (the exception's class name only; nothing from the exception reaches a page) and answer the way the route already answers a target that is not there: a flash saying "Target not found." on the page routes, a 404 on the JSON ones. An unreadable ledger is deliberately not an empty one: it plans nothing and reports "The sync ledger could not be read; the details are in Jen's log." as the sync's error, because a plan made against an empty ledger would re-add every record and lose track of which ones Jen owns. The record list and the export answer 503 in that case rather than an empty list; the page says the records could not be loaded instead of "No records for this target yet."

### Fixed: the Preview route flashed on a role refusal

Preview is fetched by the page's script and reads a JSON answer. A viewer who reached it got a 403 and a flash message, and the flash was queued for whatever page they opened next. It now answers `{"ok": false, "error": "..."}` with the 403 and queues no flash.

### Changed: the copied write gate and placeholder helper are Jen's

The private `_is_admin`, `_require_write` and `_in_placeholders` are gone. The three write routes (add, toggle, delete) are decorated with `jen.plugin_api.require_write`, with this plugin's own sentence and a redirect to its own page, so a viewer sees exactly what they saw before; `_in_placeholders` was already a one-line call to `plugin_api.in_placeholders` and the call sites use it directly. The page's `is_admin` flag is `is_admin_or_above()`. The old `_is_admin` also swallowed an import failure and fell back to reading the account's role itself; that fallback is gone, so a failure to reach Jen's own check refuses rather than guessing. Left as they are, because Jen's API has no equivalent: `_derive_subnet_id` (a plugin-local, pure walk of the subnet map, covered by the harness) and the rest of the target-visibility helpers.

### Removed: a dead map in the debounce wiring

`_debounce_pending` was written on every touch and every fire and read by nothing; the live debounce is the per-target `threading.Timer`. The map and the two statements that fed it are removed. `debounce_schedule` and `debounce_ready` stay, as the pure model the harness pins; the module docstring now says nothing live calls them.

### Documented: a column that is written and never read

`ds_targets.created_by` (the account that added a target) is recorded for the audit trail and is not displayed anywhere on the page. It is not dropped: removing a column from a released table would be a destructive migration for no benefit. The README says so.

The harness gained checks for every item: the gate refuses a viewer on the three write routes with the plugin's sentence and a redirect, the Preview refusal is a JSON 403 with no flash, a URL with userinfo is refused without echoing it (and four URL shapes that only contain an `@` after the host are not mistaken for one), the page prints no userinfo, a failing database leaves `_load_target` and `_ledger_for_target` returning None with a class-name-only log line, an unreadable ledger plans nothing, and the record list and export answer 503.

## [1.1.2] - 2026-10-11

Fix. `requires_jen` stays 5.68.0; the `scoped` argument of `send_alert` this release uses is in Jen 5.68.0-beta.9 and later.

### Fixed: the sync-failed alert no longer goes to channels limited to some subnets

The *DNS sync failed* alert is about a whole target, not one subnet: a target syncs the records of every subnet it is set up for, so the alert
has no subnet id. Jen delivers an alert with no subnet id to every channel, a channel the operator limited to particular subnets included, and
this alert's text carries the error summary, which names the hostnames that failed from any of those subnets. A person who limited a channel
to one subnet was receiving the names of hosts in the others. The alert is now sent with `scoped=True`, which Jen reads as "about something that
cannot be placed in one subnet": only channels with no subnet scope receive it. The text, the cooldown and what the page shows are unchanged.

The harness runs the real `_maybe_alert` and requires `subnet_id=None` with `scoped=True`, the cooldown stamp still written, and nothing sent
inside the cooldown.

## [1.1.1] - 2026-10-07

Requires Jen 5.68.0 (a 5.68.0 beta satisfies it); the constant this release uses is exported by Jen 5.68.0-beta.18 and later.

### Fixed: the leases that feed its DNS records

The lease source asked Kea for rows at `state=0` and nothing more. Kea keeps a lease row at state 0 past its expiry until reclamation removes it, so a lease that had already ended still supplied a name, and a name for an address that was no longer in use was pushed to Pi-hole or AdGuard Home (and kept there while the stale row lingered). The query now uses Jen's one definition of a current lease, `ACTIVE_LEASE4` (state 0 AND not past its expiry), exported through `jen.plugin_api`; the harness proves the query asks for it and that the plugin never spells the predicate itself.

## [1.1.0] - 2026-10-04

Requires Jen 5.68.0 (a 5.68.0 beta satisfies it): this release registers an **investigation provider**.

### Added: the DNS records that carry its name, on Jen's Investigation page

Jen's Investigation page (`/client`) now has a "What else Jen knows" section on its Overview, and this plugin
contributes one card to it: the records DNS Sync pushed under the client's hostname (its own, its leases' and its
reservations') or onto its addresses, on each target, and whether each one matches what the client holds. A record whose
name is the client's but whose address is not, or whose address is the client's but whose name is not, makes it a
"Needs a look" card, and its sentence also joins the Investigation page's one-line answer. A client with no record adds
no card.

A target is shown only to a caller who may see one of its subnets, and a record only to one who may see the subnet its
address lives in; an address in no Kea subnet is for unrestricted callers only. Both are judged in the plugin's own
filter against the scope Jen handed over. `requires_jen` moves to 5.68.0 because the hook does not exist before it.

## [1.0.4] - 2026-09-27

Jen's Q100 sweep: onto Jen 5.65.10's shared helpers, plus a query-count fix from the same audit.

### Fixed

- `_desired_for_target` (what a sync run actually pushes) and `_targets_touched_by_event` (which targets
  a lease/reservation change should debounce a sync for) each read a target's `subnet_ids` with a bare
  `json.loads`, while the helper written to tolerate an already-decoded list or malformed JSON
  (`_target_subnets`) sat unused two functions away. Both go through it now, so a stored value that isn't
  a clean JSON string array no longer raises out of either path.
- The target list ran one full ledger query per target just to show its record count. It is one query for
  every visible target's records now, counted in Python.

### Changed

- The dynamic `IN (...)` placeholder builder delegates to Jen's shared `in_placeholders()`.
- `tools/test_plugin.py` checks both tolerant reads directly and that the record count is one query.

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
