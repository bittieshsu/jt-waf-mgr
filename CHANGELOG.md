# Changelog

**English** · [繁體中文](CHANGELOG_zh-TW.md) · [日本語](CHANGELOG_ja.md)

## 0.4.75 (2026-11-16)

- Threat intelligence: one product can be listed more than once (two Zimbra servers on different versions), each
  entry with its own sites (a site in one entry only). The search sees one line per product with every version
  ("10.1.20, 10.1.21") and counts it as affected when any of them is; never the sites. A refused entry says why under
  the form, and the sites field says how to give several (commas or spaces). Database schema 16.
- Threat intelligence: an opened threat reads better: the summary first, then three panels (versions and the fix with
  the version here, the attack and the precaution rule, exploitation with the full conditions), the sources as one
  line each, the buttons at the end.
- System check: lists show one chip per item (a long one opens with "N more"), long values break only at / - _ . and
  never inside a word, times stay on one line; "generated_at" has a name.
- Changes: the "approve the selected" row lines up (check box, note, button at the end).
- Temporary IP blocks: the "Sites tried" heading explains ×N (the address's WAF events on that site in the 7 days up to
  the block); a table heading can carry such a note.

## 0.4.74 (2026-11-16)

- Threat intelligence alerts are worded in the notification and interface language: an alert keeps the CVE, the
  software, its version and whether it affects this site, and the message and the Alerts page build the sentence from
  them (the English sentence stays in the audit trail and the log records). A version the model gave as "unknown" is
  no version: the alert says the version here is not known instead of "Zimbra unknown", and no "remove the rule"
  reminder comes from it.
- Threat intelligence: the "Guess again" button shows a spinner while it works; the page speaks of web applications
  rather than software.
- Notifications: clearer wording for "affects the version here"; full-width colon in the Japanese threat title.
- uninstall.sh removes every jt-waf-mgr unit that is installed (before, the CRS updater's units were left behind);
  `--purge` also removes the apply program's state and the upgrade backups.
- Release checks: a fresh install, uninstall keeping the data, reinstall and `--purge` leaving nothing behind are now
  part of every release test.
- `settings export --secrets` writes keys and passwords only to a new mode-600 file (`-o FILE`), never to the
  terminal. The site version check uses TLS 1.2 or newer, like every other TLS client of the program (code scanning).

## 0.4.73 (2026-11-16)

- War room: no demo banner taking a row; in demo mode the top bar's button is the sign (amber, filled, "Demo on" with
  a pulsing dot; its tooltip says the board is made-up data, a click leaves the demo); a link clicked in demo mode says
  so for a moment at the top right. The event intensity card is on the map page only: on the other pages their main
  card takes its row (the globe is much larger). The globe's controls are a column of icons on its right edge (names
  and keys in the tooltips), and the globe itself is a little larger.

## 0.4.72 (2026-11-16)

- Threat intelligence: the versions of the applications behind the sites are read from the applications themselves
  before each search (one request through this host's nginx, the certificate checked): Nextcloud, Zulip, Odoo,
  Grafana, Open WebUI, WordPress and draw.io (checked on running installations), and ownCloud Infinite Scale, Gitea /
  Forgejo, Rocket.Chat, Mattermost, Jenkins, Matrix (Synapse), Seafile, Harbor, Mastodon, Collabora Online and
  LibreNMS (with its API token, a new write-only setting). A version a person typed is never replaced; one read before
  follows upgrades (audited). The threat intelligence page and the project site (How it works → Versions) list which
  applications tell their version and how to read the others on their host. Univention Corporate Server is now
  recognised in the access logs.
- Threat intelligence page: the second-tier card shows two panels of one width, the structured sources as on / off
  badges; when one is off, a link opens Settings → Second-tier LLM (threat intelligence) (the hint named a card that
  does not exist).
- Security policy: from this release on, every exploitable issue fixed in a release gets a GitHub Security Advisory
  (SECURITY.md).

## 0.4.71 (2026-11-16)

- War room: the sixth page is named "AI analysis and threat intel" (in Chinese, AI 分析與威脅情報).

## 0.4.70 (2026-11-16)

- Wording: the interface no longer says "we" or "us". In Chinese the place the war room marks is 本站 ("our site"),
  and the threat intelligence says "affects our site" (影響本站); the English war room says "Our site" and "Center
  on our site". The Chinese word for "we" is now rejected by the interface wording check.

## 0.4.69 (2026-11-16)

- War room: a "center on us" button under the globe (key C) turns it to our location and stops its spin; the globe's
  buttons have one height and some room between them; the time range also offers the last 1, 5 and 10 minutes; in
  demo mode the demo button is the state as well (one place says "demo"); the globe no longer flashes when other cards
  refresh (its canvas is only reset when its size really changes, and painted again at once); in demo mode new
  latest events are pushed in at the top instead of the whole list changing every minute.
- `jt-waf-mgr check`: whether the service can read the audit log, when a directory open only to the service's group
  hides the file from the command line, is told by when the service last read it (`audit_log_last_read`; `null` when
  that cannot tell, not a problem). 0.4.68 reported such a host as a problem.
- Release checks: the ZAP scan has a home directory and proxy port of its own (another scan on the host stopped it).

## 0.4.68 (2026-11-16)

- ModSecurity guide (three languages), after an outside review: what jt-waf-mgr may change in nginx (marked includes
  for a site's WAF and the blocked page, the IP block list); `apt install --no-install-recommends` (the connector
  recommends the distribution's CRS 3); package sources and the loaded configuration checked with `apt-cache policy`
  and `nginx -T`; the upstream ModSecurity version without the distribution's revision; comments on their own lines;
  the raw audit log may hold what the database masks; `adm` is only an example (install.sh finds the group); base
  rules can log before the CRS; a hand-installed CRS in `crs-<version>` (so jt-waf-mgr can update and roll it back);
  the optional site rule files commented out until created; testing with the real site name and a value of this
  request; reload after switching to `On`.
- A comment at the end of a ModSecurity directive line (`SecRuleEngine DetectionOnly  # ...`) is no longer read as part
  of its value (libmodsecurity ignores it).
- `jt-waf-mgr check` adds the main file(s) nginx loads (`main_config`), the audit log path, the audit-format warnings
  and `problems` in words; it exits 1 when any is found. Whether the service can read the audit log is judged by the
  groups systemd gives it (the command line runs without them).
- README and project site: a disclaimer at the end.

## 0.4.67 (2026-11-16)

- Threat intelligence: only web-facing software is followed (the web servers, the WAF and the libraries it parses
  requests with, TLS, the CRS, web applications). What an older version guessed outside that (an SSH server, the
  system's Python) leaves the list even when confirmed, its open threats are set aside and their alerts handled: a
  WAF cannot shield what is not reached through the sites. A person's own entries stay.
- War room globe: zoom with the mouse wheel, two fingers or the buttons (0.6x to 3x); a drag let go while moving
  keeps turning at that speed and slows down; up to 60 frames a second when the machine keeps up; the globe marks
  our place without words. The map area is larger (four latest events, the timeline fills its card, a slightly
  larger globe). The map subtitle reads "Outside sources → our WAF". The state, the range and the buttons at the
  top have the same height. `?page=globe` (or another page) opens the board on that page.
- Wording: the decision "fallback" is now 標記後封鎖 in Chinese (a rule marked the request, the last rule blocks).
- Project site: the top picture rotates through the dashboard, the war room and the request volume (arrows, dots
  and arrow keys switch by hand); the screenshot grid has an even number (the war room globe added); thumbnails are
  full-size lossless WebP (small text was blurred).
- War room, more: a switch in the top bar shows the blocked events alone or with the logged ones (`?only=blocked`,
  key B; the server counts them so); keys like jt-ipam's board (1–7, arrows, PgUp / PgDn, Home, Space, R, Z, B, D,
  F, + − 0, S) with an H button and panel listing them; rankings, site rows and the score-only list slide to their
  new places, numbers roll, bars grow and shrink smoothly, a new minute slides the timeline left; pages change with a
  short slide and fade; the threat-intelligence list is in columns; a proper full-screen icon; on screens narrower
  than 1400 px the top bar's buttons show icons only (one line).
- Threat intelligence page: the second-tier card is two aligned groups (model and search, structured sources).
- The help menu says "Project site".
- Installing: one fixed place, `/opt/jt-waf-mgr-install/current` (every release unpacks there; install, upgrade,
  rollback and removal run there); the README and the project site download the release from GitHub, verify and
  unpack it there, and list where things are after installing (the program stays in `/usr/lib/jt-waf-mgr`). The
  site fills the version into its commands; the release checks catch an old version in the README commands.
- The date fields of the filters stay on one line (the full value in the tooltip).
- Project site, how it works: the enlarged diagram fills the window and zooms (+ − fit, Ctrl+wheel, drag to move).

## 0.4.66 (2026-11-16)

- War room: a time range in the top bar: live (the last 30 minutes, as before) or the last 15 minutes, 1, 3, 6, 12 or
  24 hours, 7 days. Kept in the address (`?range=24h`) so a wall screen can open it directly; new events keep coming in
  every 5 seconds. The timeline and the site cells keep their number of steps, each covering more time.
- War room: the big numbers roll when they change: down when they grew, up when they shrank (only the digits that
  changed; no motion for viewers who asked for less).
- War room: the maps and the globe mark where we are as "Us" (Settings > War room: latitude and longitude; the name is
  now optional and shows as "Us · name").
- War room: demo mode (a button at the top, or `?demo=1`): made-up traffic of sites under steady attack, with waves from
  one country now and then, on every page (maps, flow, sites, review, AI and threat intelligence, alerts and changes).
  It is made in the browser: nothing is read from or written to the server, a striped banner says "demo" the whole
  time, the state shows "Demo", and links do not open. For showing the board without real data.

## 0.4.65 (2026-11-16)

Fixes from a review of the last versions:

- Settings: switching the second-tier provider could bring back a saved API key together with a new server address
  typed in the same save, sending the key to that server. A stored or brought-back key now always needs entering
  again for a different server, also through the import and the command line.
- War room: only names a site serves are shown (internal-only sites keep their alias); any other Host (a trailing
  dot, an address, a wildcard match, a name an outsider sent) shows as "other". One snapshot is computed at a time
  for all screens. After a database restore the wall starts over instead of waiting for higher event ids.
- Carried approvals: only when the change's own added and removed lines are exactly those approved, by a person who
  may still approve, never for one's own change.
- Threat intelligence: KEV, OSV and NVD trouble (a cut download, an odd answer, a full disk) leaves that source out
  of the run instead of failing it. A threat that becomes urgent later (its preconditions confirmed) raises the
  alert then.
- Settings import: the preview never compares a key or password with the file.
- Command line: `settings export -o` only creates a new file (mode 600); `settings set` keeps text as typed (digits in
  an id or a password stay text) and says when the web service needs a restart; a missing id is a clear error.

## 0.4.64 (2026-11-16)

- Threat intelligence: NVD scores (Settings > threat intelligence, off until switched on). After each search the
  intelligence job asks the NVD API for the CVSS score and weakness (CWE) of each CVE found -- only the CVE id is
  sent, one request every 6 seconds, at most 20 a run, answers kept 7 days. The official severity replaces the
  model's guess (both are kept); the intelligence page shows "NVD 9.8 · CWE-78" under the severity.
- The war room in README and on the site now shows arcs to an entry point (synthetic destination in the test data).

## 0.4.63 (2026-11-16)

- Threat intelligence: OSV queries (Settings > threat intelligence, off until switched on). Once a day the
  intelligence job asks osv.dev's query API which known vulnerabilities affect the exact Debian / Ubuntu package
  versions of the confirmed software (source package, installed version and release are sent; no bulk download;
  answers kept a day). They are given to the model as a hint, with a reminder that a distribution may patch without
  changing the upstream version.

## 0.4.62 (2026-11-16)

- Threat intelligence: the CISA Known Exploited Vulnerabilities catalog as a structured source (Settings > threat
  intelligence, off until switched on). Once a day the intelligence job downloads it from cisa.gov (about 1.5 MB),
  checks it is the catalog and replaces its copy only then. A vulnerability in it counts as exploited in the wild
  (noted as the evidence), and its entries for the confirmed software are given to the model to check against our
  versions. The intelligence page shows the catalog's size and date.

## 0.4.61 (2026-11-16)

- War room: on a narrow screen the page tabs stay on one line and scroll sideways (seven tabs no longer take half the
  phone screen).
- README and the project site show the war room.

## 0.4.60 (2026-11-16)

- Event list: an attack flood is one row. The same request (source, site, method, path, rules, outcome) again within
  a minute folds into the row of its newest event, marked "×n" with the time span; a switch above the list shows
  every event again (remembered in this browser). Only the list folds: every count, chart, analysis and check still
  counts each event.
- Second-tier LLM: Google Gemini as a provider, through Google's OpenAI-compatible endpoint (the URL can stay empty;
  a Google AI Studio key and a model are needed); it searches through the MCP server.

## 0.4.59 (2026-11-16)

- War room, third stage: the last two pages. AI and threat intelligence: the latest event analysis (events looked at,
  candidates, the model's answers by kind, proposals, how long) and the threat intelligence (open threats, exploited
  ones, what affects us, what a virtual patch covers, software waiting for a person). Alerts and changes: open alerts,
  changes being checked, waiting for approval and applied in the last 24 hours, as cards that open in a new tab.
  Ids, kinds, states and times only: no path, reason or summary text on the wall. Nothing on the board starts an
  analysis or writes anything. All seven pages of the design are in.
- API: `GET /warroom/ops` (viewer).

## 0.4.58 (2026-11-16)

- War room, second stage: three more pages. Decision flow: bands from source (outside / inside) through what decided
  (confident rule, fallback refusal, CRS score, other rule, logged only) to the outcome, one event counted once; a band
  or a node opens those events. Site activity: each site's events in 2-minute cells over the 30 minutes, with blocked
  and logged, where the events concentrate, and the focus sites that had none. False-positive review: what the CRS
  score alone blocked, by site, and the internal and outside logged-only events to look at, each a link to the event
  list with the same window. Rotation goes through all five pages.

## 0.4.57 (2026-11-16)

- Administration from the command line: `jt-waf-mgr blocks | alerts | changes | settings | tokens | intel | review`,
  the same rules as the web interface. A write names the person (`--as`, an existing account with the role needed);
  the audit trail records that person with `cli` as the source; approving one's own change, or a loosening one, asks
  for what the web interface asks (single-admin mode, `--totp`). `--json` for machine-readable output.
- Settings export and import (Settings > Export and import settings, or `jt-waf-mgr settings export / import`): one
  JSON file with every setting of the settings page and the change workflow's. Keys and passwords only with a fresh
  one-time code (the file says so). Import shows the file next to the current values (only those that differ by
  default), you tick settings, whole groups or all, and only those are written -- all or none, with a one-time code,
  each audited, plus one "settings imported" record.
- Several tightening changes approved at once: tick them on Changes > Pending approval (or "all"), one click; each
  under the same rules as one by one. A loosening change is still approved on its own page.
- An approval carries over: a tightening change approved while another one was being applied is checked again
  against the new version and, unchanged and passing, applied without a second click (audited as carried).
- Configuration text (nginx lines, the fail2ban example, nginx -t output, sandbox messages, settings values) gets
  syntax colours; the UI check asks for it.

## 0.4.56 (2026-11-16)

- War room, first stage: Overview > War room opens a board of its own in a new tab, for a wall screen (dark, no admin
  menu). Two pages: a flat world map and a 3D globe you can turn, with the same numbers: the last 30 minutes per source
  country (events, blocked / logged, different sources), events a minute, the latest events; a tracer for each new
  batch, from the country to your WAF's location (Settings > War room; without it only the sources are drawn).
  Rotate, pause the animation, freeze the data, full screen; arrow keys switch pages, Space pauses, Esc closes a
  country's details. It tells live, quiet, not collecting, disconnected and catching up apart. Read only.
- The board's API (`GET /warroom/snapshot`, `GET /warroom/events?after=`) leaves out the source address, the path, the
  query and the headers; a site nginx serves only to internal networks gets an alias. Spec: docs/spec/WARROOM.md.

## 0.4.55 (2026-11-16)

- Filter and exclude everywhere: a right-click on a value in any table opens the value menu (filter by / exclude this
  value for that table, shown as chips above it; copy; open a link in a new tab). The menu's first row shows the value
  and what it is. Traffic: a site can be excluded too (`not_host`).
- Help is a menu: user guide, product website, how it works, API manual, changelog, report a problem, source code.
- Number tiles look like the dashboard's on every page (IP lookup with a 7- and 30-day trend, CRS, WAF model, periodic
  review); the UI check rejects plain tiles. The role next to your name is an icon (its name in the tooltip).
- Event AI analysis: the steps as they happen (queued, started, gathering, asking the LLM with the time waited,
  checking) with a spinner; the LLM server and model used; a 502/503/504 from the server is retried once; failures
  explained. Every "loading" has a spinner.
- Event detail: a card title and facts in aligned rows. Periodic review: focus sites in a table. Long values (site
  patterns in the rules list, nginx lines in country limits, the request column of the events) stay inside their
  column with "..." and the full text on hover.
- Sites: "outside requests, 7 days" says what it counts (every request from outside, any country, answered or not),
  and for a site under a country limit how many of them the country rule blocked.
- IP blocks: the sites each address went for before it was blocked; the places the list does not cover are a table,
  and an `internal` location (the blocked page, error pages) is no longer listed. Locations marked `internal` no
  longer count as skipping the WAF either.
- Threat intelligence: a vulnerability's preconditions (a C library, a build or configuration option such as sshd
  without PAM) are compared with a few host facts sent with the software list (operating system, architecture,
  C library, sshd's UsePAM): not met means not affected; not confirmed means a warning to check instead of the urgent
  path. A version match alone no longer raises a critical alert.
- Software guess: ActiveSync alone is Z-Push (not where Exchange, Zimbra, SOGo or Kerio answer it); LibreNMS from its
  API; Zulip no longer from `/api/v1/events`.
- Architecture diagrams (user guide and website) show the second-tier LLM, the access logs, the download services and
  their sources; "Admins + tokens". Wazuh active response: an example script that blocks through the API
  (deploy/wazuh/active-response). Each GitHub Release carries the SBOM as its own file; the website links to it.
- Wording: zh-TW uses 加強 and 被外部修改, denylist / allowlist terms in every language (preflight and the i18n check
  refuse the old ones); every audit action has its name in all three languages (checked).

## 0.4.54 (2026-11-15)

- Large traffic: the dashboard reads hourly counts kept by SQLite triggers (by site, origin, outcome, decision,
  attack type, rule and source) plus the partial hours at both ends from the events themselves: the same numbers,
  without scanning every event of the window (synthetic 400,000 events: 7 days 6.0 s -> 0.95 s, 24 hours 0.96 s ->
  0.34 s; the more concentrated the traffic, the larger the gain). The upgrade counts the stored events in (schema 15).
- One dashboard answer is shared by every screen for 15 seconds (or while no new event arrives, up to a minute).
- systemd: the web service runs below nginx (Nice 5, CPU and IO weight 50) and the background jobs lower still
  (Nice 10, weight 20): a busy host serves the sites first; an idle one sees no difference.
- Software guess: host packages limited to web-facing software (the web stack, other web servers, PHP / Node.js /
  Java, web applications installed as packages: about 50 products; glibc, bash, git, mail and database servers and
  the like are no longer guessed). Zimbra is also recognised from its sign-in page (a monitoring check sees only that).

## 0.4.53 (2026-11-15)

- Confirmations use the app's own dialog (the page's colours and language; delete / revoke in red, starting on
  "cancel"; Esc or a click outside cancels) instead of the browser's; the UI check rejects window.confirm / alert /
  prompt.
- Sites > Blocked page: "Preview" opens the page in a new tab with a sample request id, site and time (its own
  sandboxed policy: only its inline style, by hash).
- Second-tier LLM: switching provider saves at once and keeps each provider's server, API key and model (the key on
  the server only): switching back brings them back. "Test connection" next to the model tests the LLM only; the MCP
  server has its own button.
- Software guess: a guessed entry renamed by a person (Exchange -> Z-Push) is not guessed again; Exchange is no
  longer guessed from ActiveSync alone (Z-Push, Zimbra and others answer it too).
- Navigation: "Overview" is a menu; the current overview is its "Dashboard" (a live war-room board will join it).
- Overview and traffic: the range buttons are as tall as the site picker. Settings > Country lists: the four facts
  side by side, the lists in use as a table of their own.
- Chinese interface and documents: full-width semicolon, comma and colon in Chinese text, a space after a half-width
  ")" followed by a word (the i18n check rejects the old forms).
- README and project site: the three ways to use it (nginx as the web server, as a reverse proxy, or both on one
  host), with a diagram; the site's threat intelligence card now says the second tier writes its own virtual
  patches.

## 0.4.52 (2026-11-15)

- Software guess: about 300 applications instead of 43 (identity, mail and groupware, files and documents, chat,
  CMS and shops, ERP / CRM / service desk, development, monitoring and security, virtualisation, storage, network
  and VPN gateways, application servers, home and media), plus PHP / ASP.NET / Java / ColdFusion as a last resort;
  about 160 host products instead of 11 (glibc, OpenSSH, web, database, mail, DNS and VPN servers, container
  runtimes, ...; versioned package names such as php8.2-fpm or postgresql-15 included).
- The signatures moved to a data file (jtwafmgr/data/software-signatures.json); each carries sample paths, and a
  test checks that every sample is guessed as its application and that common paths (/api/status, /dashboard/,
  /assets/index-*.js, ...) are guessed as nothing. Too-wide signatures found that way were narrowed (Uptime Kuma no
  longer matches any Vite site's /assets/index-*.js; Proxmox Backup Server is no longer hidden by Proxmox VE).

## 0.4.51 (2026-11-15)

- Software guess: Zulip's API (/api/v1/messages and the like) is no longer taken for Rocket.Chat (its signature
  now has to match a whole path segment); the same for Mattermost.
- A guessed entry you remove stays removed: "Guess again" leaves it out (adding the name by hand takes it back).

## 0.4.50 (2026-11-15)

- Second-tier LLM settings: the API key comes before the model (the model list needs the key), as on the first tier.
- The provider's own web search also works with OpenAI's own API (Responses API web search, plus the program's own
  page reader so "exploited" still needs a CISA page read in that run). Other OpenAI-compatible servers: use MCP.
- MCP search server: its own "Test connection" button (no LLM needed): it answers and offers web_search.
- Software list: "Confirm all"; the guess counts 2xx answers only (a redirect is no sign of an application) and
  skips jt-waf-mgr's own site; guesses no longer made and never confirmed are removed. A name is enough (version
  optional).
- A product confirmed by name only: an exploited vulnerability in it counts as possibly affecting you (critical alert,
  urgent virtual patch -- still checked like every change).

## 0.4.49 (2026-11-15)

- Settings: the two LLM cards are named the same way and sit next to each other: "First-tier LLM (event analysis)",
  then "Second-tier LLM (threat intelligence)", then the scheduled event analysis.

## 0.4.48 (2026-11-15)

Fixes from GitHub code scanning (CodeQL):
- Every TLS client of the program (health checks, syslog over TLS, notifications, e-mail, the threat intelligence
  fetches) refuses anything older than TLS 1.2.
- Response headers: a CR or LF in a header value is removed before it is sent (no value comes from a request today;
  this keeps it so).
- preflight finds inline scripts and styles in the built page with an HTML parser instead of a pattern (upper case,
  odd spacing).

## 0.4.47 (2026-11-15)

- Threat intelligence settings: "Test connection" and a model list, like the first tier. The intel service does the test
  (the web service never connects out): the models offered, a one-word answer, and the MCP search tool. Works before
  the search is switched on.
- Value menu (like Graylog): a right-click on a value, or its small funnel icon, opens "Filter by this value",
  "Exclude this value", "Copy value" (and "Open" where there is a page). The value itself now opens its page (an
  address opens the IP lookup, a rule ID the rule page) instead of filtering. Exclusions show as chips and are sent as
  `not_<name>` (event list and overview APIs). The address card no longer covers the menu or a tooltip.
- Settings: the local LLM card is now "First-tier LLM (self-hosted)"; it serves the scheduled event analysis and the
  "AI analysis" button on an event (the text said only the former).
- Chinese text: a space before a half-width "(" after a word (checked by the i18n check).

## 0.4.46 (2026-11-15)

- Blocked page: also shown to addresses on the IP block list (the page's internal location allows everyone; before,
  nginx refused the page too and showed its own 403). Checked with real nginx and ModSecurity.
- Blocked page: the snippet and the page are jt-waf-mgr's own files: a release with newer ones offers "Update the
  page" on the Sites page (a change), instead of refusing them as edited by hand.

## 0.4.45 (2026-11-15)

- Sites: "Blocked page" -- the page blocked visitors see (three languages, with the request id to paste into "Someone
  was blocked?"), on every site at once or one site at a time, as a change a person approves: one marked include line
  per server block that serves content (blocks that only redirect or have their own 403 page are left alone); the root
  program writes the page and the snippet next to the managed rule files, nginx -t, reload, health checks, and puts
  everything back if a step fails. Replaces the sample in `deploy/blocked-page/`.
- Settings: the "Threat intelligence (second-tier LLM)" and "Periodic WAF review" cards were missing from the settings
  page (the "Settings" button on the threat intelligence page led nowhere). The build check now fails when a settings
  card is not shown on any page.
- Menu on narrow screens: the page behind is dimmed, each group is its own card with a coloured heading, and the
  current page is marked with a bar.

## 0.4.44 (2026-11-15)

- Overview: one line with the latest periodic WAF review (its verdict, blocked / logged) and a link to it.

## 0.4.43 (2026-11-15)

Fixes from an independent security review of the threat intelligence and the AI analysis:
- Rule patterns: a ModSecurity macro (`%{...}`) or a POSIX class (`[[:alnum:]]`) is refused in every rule's regex --
  ModSecurity and the Python checks would read them differently. Virtual patches get the same checks as every rule.
- "Exploited in the wild" counts only when the search read it on a CISA page in that run (else "said to be
  exploited", not urgent); urgent patches past the daily limit: at most 5 a day.
- Tokens: counted after every response, the run stops when the day's or month's limit is reached, and a run that
  fails half way (or with an unexpected error) records its end, its error and its tokens.
- fetch_url: port 443 only; the name is resolved once and that checked address is the one connected to (no second
  lookup); NAT64, IPv4-mapped and 6to4 addresses are refused.
- A threat is matched to a confirmed product by the same name or whole words (no more "nginx" matching the
  ModSecurity-nginx connector).
- Virtual patches always carry a sandbox test (on the product's site, else on a site the WAF serves; header patches
  send the header).
- Software list: a host name from the logs must be a valid name; a person's site list is kept when guessing again.
- Threat references show their site first; the event AI analysis warns when the LLM server is not on the local network.

## 0.4.42 (2026-11-15)

- System check: threat intelligence (set up, searched recently, within its token limits, a confirmed software list, no
  open exploited vulnerability that affects you).
- README and project site: screenshots of the threat intelligence and periodic review pages.

## 0.4.41 (2026-11-15)

- "Someone was blocked?" also takes nginx's 32-digit request id alone (an error page can show it); API
  `GET /events?request_id=`.
- `deploy/blocked-page/`: a page for blocked visitors in three languages with the request id, and the nginx snippet to
  use it (optional; jt-waf-mgr never writes it).

## 0.4.40 (2026-11-15)

- "Someone was blocked?" on the Events page: paste their IP address (opens the address lookup), the URL they opened
  (the site's blocked events on that path) or a request id (that one event). API: `GET /events?unique_id=`.

## 0.4.39 (2026-11-15)

- "Configuration changed outside" no longer fires when one apply wrote the managed rules and the IP block list in
  the same minute (each file is checked on its own).
- Switch the WAF on for a site from the Sites page (and off again): a change. Checks: the plan (each of the site's
  server blocks without ModSecurity, not redirect-only, none with a hand-written `modsecurity off;`) and, switching on,
  the site's recent normal requests from the access logs replayed in the sandbox with ModSecurity on. A person approves
  (switching off is a loosening). The root apply program computes the plan again, requires the same blocks and the
  same file contents as checked, adds one marked include line after each `server {` line (the snippet the other sites
  use to switch ModSecurity on, else a managed one), runs nginx -t, reloads, checks the health URLs and puts the files
  back on any failure; switching off removes exactly that line. These edits are not reported as outside changes.
- Change pages name CRS and site switches properly.

## 0.4.38 (2026-11-15)

- AI analysis of one event: a button on every event page sends the event with what is around it (the same source in
  the hour around it and over 30 days, the same site and path over 7 days with internal users and answers, the rules it
  hit) to the first-tier (local) LLM, which answers attack / false positive / unclear, how sure, why, and one piece of
  advice (block the address, block this kind of request, a narrow exclusion, watch, nothing). The advice is checked
  (an internal address is never offered for blocking; an action that does not fit the verdict becomes "watch"), and
  its buttons open the usual forms (the IP block form filled in, a proposed confident block or exclusion from the
  event). The analysis job answers it (jt-waf-mgr-analyst.path); the web service never talks to the LLM. API
  `GET` / `POST /events/{id}/analysis`.
- The IP block form can be filled in from a link (address and reason).

## 0.4.37 (2026-11-15)

- Threat intelligence writes virtual patches: for a vulnerability seen in the URL or a header (open, affects or may
  affect a confirmed version, exploited or critical / high), the second-tier LLM gives a narrow match with attack and
  normal examples; the program checks it (anchored, no slow patterns, matches its attack examples, matches none of
  the normal ones, the regression samples or common header values) and proposes an ordinary confident block, limited to
  the product's site when there is one, outside sources only, with 403 tests. Applied automatically like the event
  analysis's blocks (Settings > Change workflow, on by default); one for a vulnerability exploited in the wild that
  affects you is not held by the daily limit. A critical alert asks a person when no rule could be written or its checks
  failed. When a person updates the software to another version, an alert says the patch may be removed.
- Periodic WAF review: only outside attacks the site answered with content (2xx) are listed as not refused; probes
  answered 4xx and requests that only got a redirect (a plain-HTTP block that answers 301 before ModSecurity runs) are
  counted apart.
- Wording (zh-TW): 加強 instead of 收緊 (the check refuses the old word).

## 0.4.36 (2026-11-15)

- Threat intelligence (Events > Threat intelligence; off until switched on in Settings): a second-tier LLM -- any
  OpenAI-compatible server (left empty: the event analysis's local server) or Anthropic (Claude Messages API) --
  searches the web every few hours for new vulnerabilities in the software list, above all those exploited in the
  wild. The program guesses the list (this host's packages from the package database, the CRS version, the
  applications the sites answer for in the access logs); a person confirms it, and only product names and versions
  are sent. Local models search through an MCP server (web_search, e.g. SearXNG) and read pages with fetch_url (https
  only, an allow-list of domains, public addresses only, plain text); with Anthropic the provider's own web search and
  fetch can be used. The answer must fit a JSON schema; a threat is kept only for a confirmed product, with a CVE or
  GHSA id and https references. An exploited vulnerability that affects the confirmed version raises a critical
  alert; new ones are notified. Token limits per day and month. Its own sandboxed unit (jt-waf-mgr-intel: hourly
  timer, "search now"); the web service never talks to the LLM or the web. Virtual patches from the findings come
  next.
- Periodic WAF review: probes answered 4xx by the site are counted, not listed as attacks that got through; a
  secret or backup file name, or a source trying many paths, is not a possible false block.
- Tables open a row in place; the notification matrix has a select-all box per channel; every condition in the
  overview's filter banner has an x; "Open this page" buttons name the page ("Go to Rules").

## 0.4.35 (2026-11-14)

- New logo: a square split by an inspection gap, with the request held at the gap (no shield; readable at 16 px).
- Periodic WAF review (Events > WAF reviews; every 3 hours by default, Settings > Periodic WAF review): requests
  blocked by the CRS score alone grouped by site and path, with possible false blocks (an internal user, or no attack
  type) first; new internal hits; outside attacks that were only logged; what was done automatically (event analysis,
  changes, IP blocks); what waits for a person; one line per focus site (events, login paths, answers 429, a source
  logging in again and again). Stored, and sent through the notification channels (event "Periodic WAF review": the
  first focus site every time, the others only when something needs a look). Read-only; never request content or
  query strings. API `GET /reviews`, `GET /reviews/{id}`, `POST /reviews/run`.
- System check: twelve more items -- ModSecurity and CRS settings, background jobs (every timer and path unit
  enabled), CRS updates, event analysis, IP blocks, country lists, the DNS check, health check URLs, changes waiting
  or stuck, API tokens expiring or unused, request counts, and whether the audit log is rotated.
- Outside configuration changes: "Files" opens right under its row instead of at the end of the page (tables can
  now open a row in place).
- CRS page: the version card has a summary line (version, state, last check, check now) and a tidier list.
- Overview: the custom range buttons have the same height as the date fields; event list: the method and the path
  are aligned.
- Ubuntu 26.04 (Python 3.14): installed and tested; each request thread now closes its database connection, and a
  deprecated call was fixed.

## 0.4.34 (2026-11-14)

- The DNS job's folder defaults to "dns" next to the database (`[dns] dir` still overrides it), and the web service
  writes there only when the database's folder exists: a test with a temporary database (the release checks run the
  tests as root on the server) can no longer write into the system's folder, as one did with documentation addresses.

## 0.4.33 (2026-11-14)

- DNS check (Settings): enter internal and external DNS servers (several of each); a separate restricted job
  (jt-waf-mgr-dns, every 15 minutes, "check now") asks each of them about every site name nginx serves, detects a
  wildcard record, and the Sites and Country limits pages show what DNS knows of each site. A name only internal DNS
  knows on a site nginx lets anyone into is shown in red: hiding a name keeps no one out.
- PTR names: the same job looks up the PTR name of outside addresses (recent events, blocks, any address the pointer
  rests on) and checks it forward. The card shown when the pointer rests on an address (events, the overview, blocks,
  event details) gives its PTR name, where it is, whether it is blocked and what it did in the last 7 days.
- The sandbox runs regression samples the change refuses through the configuration in place too: a sample the rules
  in place already refuse no longer fails a change.
- The author shown for rules this system generates is "jt-rules" (the API value is still `jason_tools`).
- Project site and README: integrations (Wazuh, jt-wazuh-mgr, Graylog, other SIEM, fail2ban, chat and webhooks); a
  GitHub link in the top bar; "Home" on the architecture page; "Upstream open source" for the parts other projects
  write.

## 0.4.32 (2026-11-14)

- IP blocks: an approver can extend an active block (a new end counted from now, up to the interface maximum, with a
  reason); an admin can make a block permanent, from the list or the form (it never ends by itself; a person ends it).
  A token or a rule never sets a permanent block, and blocking the same address again never shortens one. Each
  blocked address shows its country.
- Countries without a GeoIP database: the registries' lists of the country blocks give the country of an outside
  address on every page (events, blocks, the country filter).
- Automatic blocking of sources that guess secret files also counts requests answered with a redirect although a
  confident-block rule matched (a site that redirects every path answers before the WAF can refuse; nothing is
  served). It is on by default for new installations (it acts once IP blocks are on). Such events show "redirected
  (nothing served)" and the outcome filter picks them out.
- Tooltips: one tooltip in the site's style everywhere (light and dark, keyboard focus, Escape); the browser's own
  never shows. Everything that can be clicked shows the pointing hand. Negative actions (switch off, delete, end a
  block, reject) are red; the build refuses one that is not.
- Request volume: the tiles are the overview's (change against the same length of time before, the trend, a link
  from the WAF blocks to their events).
- Country limits page: the rule id on the same line as the countries, the refusing countries as named chips, the time
  of the last refusal (it showed 1970). "Help" in the menu. The log destination's choices are chips with room between
  them.

## 0.4.31 (2026-11-14)

- Sites page: the country-limits column is one line per site (what its country rules allow or block) linking to
  that site on the country-limits page; the buttons, the changes on their way and the notes are on that page only.
  The country-limits page opens one site with `?host=`.
- Who can reach a site (Sites and Country limits pages): internal only, some countries, some addresses, a source
  check that is not understood, or inside and outside, from nginx's own checks for the whole server block (geo and
  map variables resolved), with the outside requests of the last 7 days. A name that only internal DNS knows is not
  protected by that alone: anyone who reaches the server can ask for it.
- A server block that only redirects (http to https) shows "redirect only" instead of "WAF off", and is counted
  apart.
- Configuration changed outside jt-waf-mgr: a change recorded before 0.4.30 shows the logins looked up in the host's
  authentication log when its page is opened, and says why what changed in the files is not shown.
- Top bar: theme, language, account and log out are the same height, and the account has a frame like the buttons.

## 0.4.30 (2026-11-14)

- Security: a rule limited to one site (a country limit, a block or an exclusion for a host) did not match the site's
  name with a trailing dot ("example.com."), which nginx serves as the same site, so such requests skipped it. New
  and changed rules match it (and a port). **Rules already applied keep the old text until they are changed: propose
  a "modify" with the same settings for each country rule (it counts as a tightening).** Country limits must name the
  site exactly.
- Known limit, documented: a request line with a full URL ("GET http://example.com/ HTTP/1.1") is routed by that URL
  whatever the Host header says, and nginx gives ModSecurity only the path, so no ModSecurity rule can tell which site
  it is for (HTTP/2 can do the same with :authority). Where a country limit must hold against such requests (a site
  reached directly, not through a CDN), keep a check in nginx (a geo variable and `return 403`) as well.
- Country limits by site (new page under Rules): every nginx site with the countries that may reach it or are
  blocked (names in the interface language), whether the WAF runs there, locations that skip it, nginx's own access
  limits, what the rules refused in the last 7 days and from where, the changes on their way, "modify", "switch off"
  and "add limit" (also for each name of a site that no rule covers yet). Rules and changes that match no site are
  listed apart. The Sites page has a country-limits column too, and the country list card says which countries and
  which sites each list file is for.
- Changing a country limit is a tightening when it covers the same site the same way and refuses at least what it
  refused before (fewer allowed countries, or more blocked ones) and exempts no new address; anything else is a
  loosening and needs a person. A country change is never applied automatically. The change form's preview shows the
  direction the change will get.
- A block by a country rule counts as a confident block (it was listed with the "CRS score only" blocks, the likely
  false positives); stored events are corrected once.
- Configuration changed outside jt-waf-mgr: the alert names the files and who was logged in to the host meanwhile
  (from the host's authentication log: account, source address, key or password, sudo commands); the change's page
  shows the logins and what changed in each file. File contents are stored with secret-looking values masked (new
  table, schema 10).
- The sandbox fails the check rather than leave out a site's samples when it has no address of an allowed country to
  send from, and never sends from an address the country rules always let through.
- Nothing private leaves: the pre-push check looks at every commit being pushed (its message, author and committer,
  every file it adds or changes against the PUBLISH.txt allowlist and the privacy scan, merges included) and every
  tag (message and tagger). Private networks, addresses at the end of a sentence, upper-case mailboxes, more key and
  token formats and UTF-16 text are detected; binary files other than PNG and WebP images are refused; the marker
  that allows an address on purpose never lets a private name or a key through; without the private denylist the
  hooks refuse instead of checking less. The release notes are scanned, and the tarball is checked against its
  checksum and scanned again, before anything is sent to GitHub. New tests (`tests/test_publication.py`) and a test
  plan section on what is published and what checks it.
- Layout: one accent line on cards (the status colour or the attention colour was a second line next to the title
  bar's), the CRS page's version and path and the update switch and its explanation no longer run together (and
  eight other places with the same lost space; the build refuses that pattern), the analysis timeline's ticks no
  longer cross its label, space between the registries table and the buttons below it. The browser test checks
  every page for a doubled line.

## 0.4.29 (2026-11-14)

- Country blocks: every sandbox request from outside now comes from an address that the country rules of its own site
  let through. Before, a change's regression samples all came from the country that change allows, so a Japan+Taiwan
  rule failed on the samples of a Taiwan-only site. Any change failed on the samples of a site with a country limit,
  because the usual test address is in no country. Tests written for a change get the same address, so a test that
  expects 403 is refused by the rule it tests, not by the country limit. A regression sample of a site that no outside
  address can reach is left out. CRS switches are compared the same way.

## 0.4.28 (2026-11-14)

- Country blocks: the sandbox's regression samples come from an address of an allowed country (the usual external test
  address is in no country, so every sample was refused and the check failed). The impact on the change also shows the
  last 7 days next to all logs kept: when nginx already has the same limit, the recent figures are what changes.

## 0.4.27 (2026-11-13)

- Country blocks (optional, off by default): limit a site to some countries ("only Taiwan and Japan") or block some
  countries. Each limit is a rule (new kind `country`) through the change workflow: the checks count from the access
  logs what it would have refused and how much of that was answered 2xx/3xx; the sandbox tests a request from an
  allowed country, from a refused one and from inside; it is never applied automatically. The internal networks, the
  known scanners, the trusted proxies and the protected list are never refused.
- The country lists come from the five regional Internet registries (APNIC, ARIN, RIPE NCC, LACNIC, AFRINIC):
  jt-waf-mgr-countries.service (new, sandboxed, daily while country blocks are on) checks every file against its MD5
  file and its own record counts and replaces the lists only when all five pass. The root apply program writes the
  lists ModSecurity reads (`/etc/nginx/modsec/jt-waf-mgr/countries/`), tests nginx and reloads, and puts everything
  back on failure; a list a rule still uses is never removed. Settings → Country blocks shows the lists and
  "Update now". API: `GET /countries`, `POST /countries/update`; sandbox tests may carry `src_ip`.
- Decision flowchart: a box shows two full lines of detail (the second line was cut); hover shows the whole text.
- After an upgrade the IP block list is written again once in the current format.

## 0.4.26 (2026-11-13)

From an independent review:
- Temporary IP blocks: the list file no longer ends in `allow all;`. nginx stops at the first allow / deny that matches
  within a level, so it switched off an administrator's own `deny` placed after the include in the same `http { }`
  (403 became 200, reproduced with nginx). The file now holds deny lines only; whether it is loaded at the http level
  is read from the include itself.
- A list that was written but whose reload failed is no longer reported as applied when it is sent again: the file
  goes back to what nginx runs, and the root program records what nginx loaded only after a reload succeeded.
- The root program also checks the protected networks, known scanners, internal networks and trusted proxies set in
  Settings (it read only config.toml before); a database it cannot read refuses the write.
- Automatic blocks of secret file scanners: only names that were refused or not found (4xx/5xx) count, at least one
  name must be unmistakable (.env, .git, keys, dumps, backups; a config.json alone never decides), and an address
  that got a 2xx/3xx for any such name is left to a person.
- First CRS installation in the sandbox: modsecurity.conf and the new CRS files go through the same audit log rewrite
  as everything else, so the candidate never writes the production audit log.
- CRS comparison counts any 4xx/5xx as refused (sites refusing with status 406 or 400), not 403 only.
- Tests that need a GPG test key are skipped where gpg cannot make one.
- Interface: the request volume page's site picker sits in the filter row; 「多擋/少擋」 became 「新增封鎖/不再封鎖」.
- The "how it works" page lists the three automations with their switches, including what the automatic IP block
  reads and when it holds back; request volume notes that sites sharing one combined log count under (default).

Also:
- Login page: after an upgrade the reload notice sits right above the login box, as wide as it (it used to stretch
  across the page with the button at the far right).
- Project site: more room between the menu entries; the three language buttons are one language button with a menu.
- LLM advice: Qwen 3.8 or later, Gemma 4 or later (older versions are not recommended); Llama dropped from the examples.
- The apply summary after a reload no longer says "old workers still draining after 0s" when it does not wait: it says
  how many old workers are still finishing open connections. Documents: a temporary IP block applies to new requests
  from the reload on; connections already open (WebSocket) last until they close.

## 0.4.25 (2026-11-13)

- Chinese interface and documents: 「封鎖」 everywhere instead of 「阻擋」 (the confident block is now 「確定封鎖」); the
  interface check refuses the old word.
- Program rules for the event analysis (no LLM needed): a secret or configuration file name asked for from outside
  only, never answered 2xx and not used internally is proposed as a confident block by the program itself; such
  candidates are no longer sent to the model. Without an LLM the analysis now still runs, with these rules only
  (`analyst.rules`, on by default; the Analysis page says which mode runs).
- Automatic temporary IP blocks for sources that guess secret files (off by default; Settings > Temporary IP blocks): one
  external address asking for 5 different secret or configuration file names within 60 minutes is blocked for 24 hours
  on every site; at most 30 such blocks an hour; an address a person unblocked is left alone for 7 days.
- "Configuration changed outside" no longer fires for jt-waf-mgr's own apply: files equal to a version that is written
  but not yet reported (the apply program waits for old nginx workers) are jt-waf-mgr's.
- Interface: the AI tag is readable in light mode; toggled buttons are solid; the change workflow settings are laid
  out in rows like the others; health check URLs can be picked from the sites nginx serves; a timeline shows the
  scheduled analysis (interval and window) as the values change; the GeoIP card's buttons are full size; long
  summaries no longer push a horizontal scrollbar into the change and alert lists; missing labels in the
  configuration card.
- Rule authors: a setting for who wrote the rules imported at adoption (the site, or Jason Tools when Jason Tools
  wrote them before adoption).
- Project site: an alerts section and the change list next to the workflow steps (synthetic data).
- Temporary IP blocks, how to connect: the Blocked IPs page has the steps and a ready fail2ban action (with this
  server's address filled in); the README has the same action, and the project site an "Optional: temporary IP
  blocks" install block.

## 0.4.24 (2026-11-13)

- Temporary IP blocks (optional, off until switched on): other systems block a single address for a while through
  the API (`POST /api/v1/blocks`, scope `blocks:write`; `DELETE /api/v1/blocks/{ip}` ends the token's own), approvers
  block addresses or ranges up to /24 or /64 on the new Blocked IPs page. The root apply program writes one nginx file
  of `deny` lines (at most once a minute, tested with nginx -t, the old file put back on failure) that the
  administrator includes once inside http { }; it covers every site, also those without ModSecurity. The page shows
  whether the file is really loaded and which servers or locations it does not reach. Defaults 24 hours, at most 7
  days from a token and 30 days by hand, 500 active, 200 per token, 60 new per token and hour; internal networks,
  known scanners, trusted proxies and a protected list (for example a CDN) are never blocked, checked again by the
  root program. Every add, extension, removal, refusal and expiry is audited (`block.*`). The IP lookup shows whether
  an address is blocked now.
- The project site lists what is inside and who wrote it: the WAF engine and detection rules (not ours, with their
  licences), jt-waf-mgr, the rules Jason Tools writes, bundled third-party code and optional outside data.

## 0.4.23 (2026-11-13)

- Request volume (Events > Request volume): every request in the nginx access logs counted per site and hour (2xx,
  3xx, 4xx, 5xx, 403, 444, 429, external, bytes) next to what the WAF blocked and logged, so the WAF numbers have a
  denominator. Numbers only: no address, URL or user agent is kept. The web service reads the live logs where it
  stopped (inode and offset, stored with the counts in one transaction), finishes a renamed file through its inode,
  re-reads one truncated in place, takes the site from the file name and caps the sites a forged Host header can
  create. On by default; switched off, and its optional alerts (a site at N times its usual hour, or many 5xx
  answers) set, under Settings > Request volume. API: `GET /api/v1/traffic`.
- The rule list shows who wrote each rule: OWASP CRS, an OWASP CRS plugin, a third-party plugin, ModSecurity base
  settings, Jason Tools (rules generated from a form and the Jason Tools rule pack) or this site (hand-written), with
  a filter and counts. API: `author` on `GET /api/v1/rules`.
- API manual for integrations (docs/API.md, three languages): tokens and scopes, errors, every endpoint a token can
  call with examples, and a script that proposes a confident block.
- Documentation: connecting to the management interface (port, the example vhost, TLS certificate options, first
  login); jt-waf-mgr installs the OWASP CRS itself (a new host needs only nginx and ModSecurity) and never writes nginx
  configuration; the recommended LLM for the event analysis; account recovery commands.
- Wazuh rule drafts: rules for a failed CRS signature and a staged CRS release; refusals now match `token.denied` too.

## 0.4.22 (2026-11-13)

- OWASP CRS updates, step 3: a host without the CRS. The check stages the newest 4.x release that has waited; the CRS
  page offers "compare in the sandbox and propose installing CRS <version>" (the same requests without and with the
  CRS). Once approved, the root program installs crs-<version> next to the main ModSecurity file, links crs to it,
  creates crs-setup.conf from its example when there is none and adds the two Includes right after modsecurity.conf;
  nginx -t, reload and health checks, and any failure takes everything out again. The ModSecurity installation guide
  mentions this way.

## 0.4.21 (2026-11-13)

- OWASP CRS updates, step 2: on the CRS page an approver proposes switching to the downloaded and verified release, or
  back to a version kept on the host. It is a change: the sandbox runs the same recent requests (and the regression
  samples) through the CRS in use and the other version and lists what is newly blocked or no longer blocked; a person
  other than the proposer approves (never automatic). The root program then reads the staged tarball without
  following links, checks its SHA-256 and the CRS signature again, unpacks it itself, refuses it unless its files are
  exactly the ones compared, points the crs link at crs-<version> (a plain crs directory becomes crs-<version> + link
  on the first switch), tests and reloads nginx, checks health and switches back on any failure. The three newest
  versions are kept. When applied, the "CRS update ready" alert closes. API: `POST /api/v1/crs/updates/propose`.

## 0.4.20 (2026-11-13)

- OWASP CRS updates, step 1 (off by default; Settings or the CRS page: "Keep the CRS current from here"): a new
  sandboxed unit, jt-waf-mgr-crs (daily, or "check now"), takes the newest release of the major version in use once
  it has been out `crs.wait_days` (7), downloads its minimal tarball and signature, keeps it only when the signature
  is valid and made by the pinned CRS release key (shipped inside the signed program), unpacks plain files only into
  a staging area with a manifest, and opens a "CRS update ready" alert. Nothing in nginx changes yet: comparing it
  in the sandbox and switching to it (approved by a person) come next. A bad signature is audited as critical.
- CRS page: "CRS versions and updates" with the version in use, the versions on the host, the newest release and
  when it can be used, the downloaded and verified one, and a warning when another program also updates the CRS.
- API: `GET /api/v1/crs/updates`, `POST /api/v1/crs/updates/check`; CLI: `jt-waf-mgr crs-update`.

## 0.4.19 (2026-11-13)

- Log servers (syslog / SIEM): up to 8 destinations, each with its own address, protocol (local socket, UDP, TCP,
  TLS), record format (JSON, CEF, LEEF 2.0, GELF 1.1, key=value), syslog header and content (audit records, WAF
  events, alerts), its own queue, retries and counters. WAF events and alerts can now be sent too. "Send a test"
  sends one sample record as entered and shows exactly what went out. Destination 1 keeps the existing settings.
  API: `GET /settings/syslog`, `POST /settings/syslog/test`; settings `syslog.payload`, `syslog.content`, `syslog.more`.
- Tables: drag a column header's edge (or use the arrow keys on it) to set its width, remembered per table; a double
  click sizes the columns automatically again. Long one-line text in a table ends in "..." (hover shows it all).
- Changes: a proposal of the event analysis is marked "AI event analysis"; an API token's proposal shows whose token
  it is and the address it came from. Long summaries are cut, a click unfolds them.
- Page headers: their buttons have one size.
- Project site and READMEs: an offline installation and upgrade guide (`docs/OFFLINE*.md`), log servers.

## 0.4.18 (2026-11-13)

- Rules list: tick rules (or "select all listed") and switch them off or on as one change; or switch a whole category
  (CRS: an attack type) off or on. CRS rules switched off need a scope: chosen sites (exclusions, picked from the nginx
  server names) or every site (an expert rule, admins only, marked high risk). A whole CRS category switched off can
  only be approved by an administrator, with a one-time code and a written reason. A preview shows the operations and
  every rule that cannot be switched here, with the reason. API: `POST /api/v1/rules/toggle`.
- Rule states: CRS's own mechanics (sampling, the localhost exceptions) no longer make every CRS rule look "off for
  some"; a rule above the paranoia level shows "not in effect" before any exclusion.
- Alerts: the analysis page has a "handle" button per alert; `/alerts?id=N` selects that alert and opens its form.
- Overview: the navigation shows its icon; the country list beside the map is one line per country, with the first ten.
- Settings: the configuration file section is a card with its own title.
- Project site and READMEs: a calmer security headline, accounts and sign-in (TOTP, lockout, password policy) and
  recovery on the host (`jt-waf-mgr user unlock | reset | passwd | disable | enable`).

## 0.4.17 (2026-11-13)

- Rules list and CRS page show whether each rule runs: on, off (removed for every request, with where), off for some
  (an exclusion for some sites or paths) or not in effect (a CRS rule above the paranoia level). Totals per state, a
  state filter, and per category (CRS: per attack type) how many rules are in each state; a click lists them.
  Managed rules that are switched off are listed too. API: `state`, `state_detail`, `family`, `summary`.
- Rules in the managed files are no longer marked "not managed" (the flag was never set).
- A folded card next to an open one keeps its own height.
- Event analysis: a false-positive candidate judged an attack (or unsure) shows "stays blocked" instead of "not
  proposed": the requests were already blocked and stay so.

## 0.4.16 (2026-11-13)

- Overview, by source address: internal / external and the country are a column of their own, aligned from row to row.
- Rules list: a long description is cut with "..." (the table no longer runs off the right edge); hover shows it
  all, a click unfolds it and a second click folds it again.

## 0.4.15 (2026-11-13)

- Event analysis: the verdict history a "false positive" must agree with counts only runs that had candidates (the last
  six within 14 days). Quiet runs, which have nothing to judge, pushed earlier verdicts out within hours.

## 0.4.14 (2026-11-13)

- Event analysis is harder to fool, after a small model called the same probes an attack, then a false positive,
  then an attack again in three runs:
  - blocked requests for names attackers look for (secrets, backups, credentials, deployment, cloud and CI files)
    from a few outside sources only, or from sources that also tried other paths, are reconnaissance by the program's
    own rule: never proposed as a false positive, never an alert, not sent to the model;
  - a path called an attack in one of the last six runs is not loosened on a "false positive" verdict ("unstable");
  - the model also sees how many paths the sources tried, the attack families they triggered elsewhere and whether the
    name is a sensitive one, with explicit guidance; the analysis asks with temperature 0.
- A disclaimer on the analysis page, in the analysis settings, the READMEs and the project site: AI can be wrong in
  both directions; loosening always needs a person, only tightening that passed every check applies on its own.
- Adoption works on a fresh ModSecurity: a side without a site rule file gets its managed file included right before
  the first / after the last CRS rules Include (the root program checks the anchor is a CRS rules Include of the main
  file and that nothing is included twice). Before, adoption failed without site files, and with only one of the two a
  managed file was written but never loaded. The page explains it, or links the installation guide when no main file
  loads the CRS rules.
- ModSecurity installation guide (`docs/MODSECURITY*.md`, three languages); Ubuntu 22.04's libmodsecurity package is
  too old (3.0.9 or later needed).
- Tests: the notification tests no longer depend on the time of day (from 8 o'clock on, the daily report added one
  message and five of them failed).

## 0.4.13 (2026-11-13)

- Tabs and segmented controls (changes, alerts and others) are as wide as their buttons instead of the whole row.
- The country map lists the first six countries beside it, with "show all"; the map stays in view while the long
  list scrolls. The overview's source address and network owner cards span the full width; an address shows
  internal / external and its country on the same line.
- An open page notices when the server was upgraded (every few minutes and when the tab comes back to the front) and
  offers a reload; until then it kept running the version it had loaded.
- Traditional Chinese: 「收編」 is now 「納管」 (adopting the rule files) everywhere; the i18n checks reject the old word.
- The UI check rejects HTML sinks (`v-html`, `innerHTML` and the like) in the front end.
- Project site: light theme in the logo's colours with a palette per card, sharp thumbnails (taken at twice the
  resolution by the browser test, `tools/make_thumbs.py`), screenshots open large in the page with a close button,
  separate install, upgrade and uninstall blocks with a copy button. READMEs: an Uninstall section.
- Test environment: the synthetic network name no longer contains markup (it showed up in screenshots).
- Settings, focus sites: the site names nginx serves are offered as one-click choices (with a search when there are
  many); typing names by hand still works.
- The guide link moves to the right of Admin in the top bar. The alerts page tabs use the same segmented style as
  the other pages. Event analysis: the alerts of a run line up in columns.

## 0.4.12 (2026-11-13)

- Event analysis no longer mistakes a scanner for users hit by a false positive. An outside address blocked on 5 or
  more different paths in the window is probing: its paths are skipped as "scanner" and not sent to the model.
  Found on real data, where one address probing `/env.bak`, `/settings.py.bak`, `/static/config.json`... produced
  false-positive alerts.
- A false positive seen from only one or two outside addresses (no internal user) gets neither an exclusion nor an
  alert (before, the exclusion was already withheld but the alert was still opened).

## 0.4.11 (2026-11-13)

- Overview: without a GeoIP database, the source list says that countries, networks and the world map appear once
  GeoIP is set up (with a link to the setting for administrators). `/overview` reports `geoip`.
- Tests close every file and test server.

## 0.4.10 (2026-11-13)

- Notification settings: "Preview" on every event of the event matrix shows the message it sends (title, text,
  facts, link), from made-up example data, in any of the three languages. `GET /notify/preview?event=&lang=` (admin).

## 0.4.9 (2026-11-13)

- Filter by country: click a country on the world map or in the country list (overview, event list), or pick one in
  the event list's filters. Works for the overview, the event list and its timeline (`country=` in the API, external
  sources placed by GeoIP).
- The address lookup map marks the location even when the address has no events in the last 30 days.

## 0.4.8 (2026-11-13)

- World map of where requests come from (GeoIP): on the overview (every country, with the top 15 listed beside
  it), on the event list (the loaded events) and on the address lookup (the address's location). Drawn in the
  page from a bundled outline (loaded only when needed); no map service, nothing leaves the browser.
- Event timelines over several days are labelled once per day, at midnight.
- System check: "CA file unreadable" and "unencrypted remote" show green when they are false; the CA line is shown
  only when a CA file is set.
- Notification and LLM calls close the connection after an HTTP error response.

## 0.4.7 (2026-11-13)

- Timelines on list pages are titled for what they count (alerts, changes, audit records, versions, deliveries,
  configuration changes); alerts use the status colours (critical red, warning amber).
- Chinese interface: "封鎖" throughout instead of the colloquial "擋".
- Event analysis: duration column shown as minutes and seconds; guidance boxes no longer drawn inside a second frame.
- Notification settings: channels that are off are clearly dimmed in the event matrix.
- Tests: every page is also checked in Japanese.

## 0.4.6 (2026-11-13)

- Alerts can be acted on: "Draft an exclusion" (false positive) or "Draft a block" (attack) opens the change form
  filled from a recent event of that site and path.
- A false-positive alert is marked handled by itself (audited, with the change number) when the exclusion proposed
  for it is applied. An attack that may have passed still needs a person.

## 0.4.5 (2026-11-13)

- Daily report through the notification channels at a set hour (default 08:00, -1 = none): events, blocks and
  logged-only requests against the previous 24 hours, external sources, busiest sites and most matched rules, open
  alerts, changes applied, analysis proposals.
- Overview: a notice with the number of open alerts (and critical ones) and a link to them.

## 0.4.4 (2026-11-13)

- The guide's architecture diagram shows the event analysis, the notifications, the LLM server and the channels.
- Five overview tiles fit one row on a tablet.
- The browser test checks phone (375 px) and tablet (768 px) widths: no page scrolls sideways, the menu reaches every
  page group; screenshots for a visual check.
- Test plan, test checklist and changelog also in Traditional Chinese and Japanese (preflight checks every changelog
  has the release).

## 0.4.3 (2026-11-13)

- READMEs and the project site show the interface in the reader's language (English, Traditional Chinese and
  Japanese screenshots, all from the synthetic test environment); the browser test checks the Japanese pages too.
- A local or UDP syslog destination that cannot be reached no longer leaves a socket open on every retry.
- API and test plan documents: event timeline, syslog settings and behaviour.

## 0.4.2 (2026-11-13)

- Syslog over TLS can trust a SIEM's own certificate authority: `[syslog] ca_file` in config.toml (root only,
  never in the web interface).
- Timelines on the configuration change history (by cause: jt-waf-mgr, automation, outside) and the versions.
- The analysis page says the timer checks every five minutes (not hourly).
- Fix (independent review): with syslog over TLS, a certificate or handshake error made 0.4.1 drop the queued
  records one by one; now every connection, name or TLS error waits and retries, and only a record the server
  cannot take (too large) is dropped. A failed TLS handshake no longer leaves its socket open. The system check
  warns about an unreadable CA file, unencrypted remote syslog and dropped records.

## 0.4.1 (2026-11-13)

- Syslog in the web interface (Settings): on / off, destination (the local /dev/log, recommended, or host:port),
  protocol UDP, TCP or TLS (server certificate checked against the system CAs), format RFC 3164 or RFC 5424 (ISO
  time, host name, message id; octet-counting framing over TCP), facility. A TCP / TLS server that does not answer is
  retried after 30 seconds instead of slowing every request; failures show in the system check.
- Teams messages: a web address in a value is never turned into a link.
- Tests clean up every temporary directory they create.
- The analysis unit and guide describe the LLM server as configured (not local) and the batched requests.
- Browser test environment: a synthetic analysis run, so the analysis page and its summary are covered.

## 0.4.0 (2026-11-12)

- Notifications: e-mail (SMTP, text + HTML), Telegram, Microsoft Teams (Workflows, Adaptive Card), Slack,
  Discord, Zulip, Nextcloud Talk (signed bot) and a generic webhook (JSON, HMAC-SHA256 signature, optional
  bearer token). Set up in Settings > Notifications with a "send a test" per channel; a matrix decides which
  events go to which channel (security and integrity, changes awaiting approval / applied / failed, event
  analysis, backups, version changes, accounts). Messages in Traditional Chinese, English or Japanese, with a
  link back to the page. The web service only queues them; a new sandboxed one-shot unit
  (jt-waf-mgr-notify: request file + one-minute timer) sends them, retries (1, 5, 15 minutes), records
  failures, limits each channel per hour and keeps 90 days of delivery records. Values from requests are
  never markup, mentions or links in a message; secrets are write-only and never in errors or the audit trail.
- Alerts to follow up: what the event analysis or the system finds that someone has to look at (an attack the
  site may have answered with content, users hit by a false positive, an attack in progress, outside
  configuration changes, integrity problems, failed applies or backups, attacks on one-time codes) opens an
  alert, listed under Alerts with a count in the menu, notified at once and reminded until an approver marks
  it handled with a note (audited).
- Event analysis: also looks at requests the anomaly score blocked and proposes the narrowest exclusion for a
  false positive (one site, one path or path prefix, the rules and request parts that matched); exclusions
  always wait for a person. Confident blocks proposed by the analysis can apply by themselves when the new
  workflow switch is on (same conditions as other automatic tightening: external sources only, clean
  evidence, sandbox passed, daily limit). An attack probe the site answered with 2xx opens a critical alert;
  the model may flag an attack in progress.
- Overview: drag across the hourly timeline to look at that time range, or pick a custom range (1 hour to 31
  days; days instead of hours beyond a week); external sources show their country and network owner.
- Every card title can be folded (button or a click on the title band), remembered per page; cards with
  buttons in the title get the title band too; card titles fit on phones.
- Fixes: chart tooltips are no longer squeezed or cut off inside small cards; a link to a settings card keeps
  it at the top while the cards above it load.
- System check: notifications (on, channels in use, failures, stuck queue); Wazuh rule drafts for alerts and
  failed notifications. Schema 7.
- Event analysis page: a summary of the latest run (events analysed, how long it took, candidates, verdicts,
  proposals, alerts, the model's main points); every run records the number of events analysed and its duration.
- Timelines with drag-to-select on the event list and the address lookup (from the server, same filters) and on
  the audit trail, alerts, notification deliveries and changes (from the loaded rows).
- Top bar grouped into drop-downs (events, rules, changes, admin) with the open-alert and pending-approval
  counts on their group.
- Rules show where they come from: OWASP CRS (version, registered automation), a CRS plugin, imported at
  adoption, a change by a person / an API token / the event analysis (with the change), a vhost, an unmanaged
  site file, the ModSecurity base settings.
- Audit trail: the raw action name and a readable one in the reader's language; details open in a dialog with
  syntax-coloured JSON.
- Filter forms: applied conditions in colour; changed but not applied ones marked and the Apply button asks to be
  pressed.
- Overview tiles: icon, label, number, trend line and a full-width trend chart at the bottom.
- Layout: system check cards (status colour, problems first, no stretched cards, missing labels translated),
  the WAF model's scoring card and the lists of uninspected sites / locations, centred table rows, the guide's
  diagram line no longer on the group border, separated badges.
- Wording: 「封鎖」 instead of 「擋下」 in Traditional Chinese; the LLM is "self-hosted" (地端), not "local" (本機).
- From the independent review: exclusions proposed by the analysis are one exact path written one way (no case,
  ./ or ../ variants) and plain request parts read only from ModSecurity's own text; none from one or two outside
  addresses; approving one needs a one-time code and a note; at most five alerts of a kind per run; chat
  messages can never mention people; webhook token and secret bound to the webhook address (scheme, host, port);
  no SMTP password without TLS; no loopback / link-local notification targets; one dead channel does not hold
  up the others; rollback stops the analysis and notification units while the database is restored; the names
  analyst, system and cli are reserved.

## 0.3.5 (2026-11-12)

- Settings cards: two-column rows (name, explanation and where the value comes from on the left, the control
  on the right), on/off switches, database choices as chips, short number fields, unsaved rows marked, the
  save result next to the buttons.
- Notices keep a clear gap to the text before and after them, on every page.
- Local LLM settings in a clear order (address and key, test, model, switch on) with a step diagram: one
  "Save and test connection" button, and the model is chosen from ONE list filled by the last test (the
  separate text field and second list are gone). Reasoning models (a <think> block before the answer) work
  for the test and the analysis.
- The analysis interval is set in minutes (at least 10); the timer wakes the job every 5 minutes. A value
  stored in hours by 0.3.4 is read as minutes.
- Analysis page: live progress while a run is asked for or running (each step as it happens, also after
  leaving the page and coming back), then the result.
- Rule texts with syntax highlighting and a formatted view (one action per line, chained rules indented), the
  exact original one click away, copy button; also in diffs, the change preview and managed rules.
- Database backups can be downloaded (admin, fresh one-time code each time, audited). The nightly backup is
  no longer skipped after a backup made by hand the evening before.
- Long lists: one way to page through them -- "next" past the loaded rows loads the next batch (the separate
  "load more" button is gone).
- Overview: focus sites with events get a full-width card each, quiet ones share one line; rules chart full
  width with readable labels; trend lines show the value at the pointer; horizontal bars keep each label next
  to its bar; the source column stays on one line.
- Settings: the read-only configuration list refreshes after a save and no longer repeats what is set in the
  web interface; links to a settings card scroll to it.
- Flows with descriptions are a vertical timeline; every card title has an icon; theme and language are one
  icon menu each; compliance values as a labelled grid; paths aligned; audit record opens into view.
- Wording: two-factor authentication (雙因素驗證); API token is 「API 權杖」 in Traditional Chinese.
- Security: a number beyond the database range in a query parameter (e.g. cursor) answered 500; now 400.
- From an independent review of the backup download and schedule: one-time codes for sensitive actions
  (backup download, approving one's own loosening) are limited to 5 wrong codes per 10 minutes (then refused,
  recorded as critical) and a code can never be used twice, also by two requests at once; the backup is
  sent in pieces (not read into memory) and checked against its recorded SHA-256; a failing nightly backup is
  retried hourly (three times) and never removes good copies; the newest three backups are always kept; the
  monitor's timers use a monotonic clock; Wazuh rule drafts for downloads and repeated wrong codes.
- Release gates: TEST_PLAN.md; a security scan of every route on every browser test run
  (tools/security_scan.py); an OWASP ZAP passive + active scan of a logged-in disposable instance
  (tools/zap_scan.py, accepted findings with reasons in deploy/zap-baseline.conf).
- Adoption is no longer recorded as an outside configuration change: the site's old rule files leaving
  main.conf are part of jt-waf-mgr's own change. (The record made at the first site's adoption stays as it
  is; the system check stops warning about it after 7 days.)

## 0.3.4 (2026-11-12)

- Settings in the web interface (admin, audited, in effect at once, stored in the database and laid over
  the configuration file): GeoIP account and license key, the local LLM server, the scheduled event
  analysis, focus sites, known scanners, catch-all hosts, paths changed by known automation, login notice,
  compliance level, password and lockout policy. Secrets are write-only (only "set, ends with …" is shown)
  and never written to the audit trail. config.toml keeps only what the program needs to start.
- Scheduled event analysis with a local, OpenAI-compatible LLM (new page "Analysis", its own sandboxed unit
  with an hourly timer and "Run now"): recent external events that no confident rule blocked are grouped by
  path, the model judges which are attack probes, and every answer is validated by the program (ids,
  regex compiles, is narrow, matches every observed form, matches no common or legitimate path) before it
  becomes an ordinary confident-block proposal. The analysis never approves anything; its proposals always
  wait for a person, also when automatic apply of tightening changes is on. Any LLM error: nothing proposed.
- "Test connection" for the LLM server runs in the analysis unit (the web service keeps no network access
  beyond localhost).
- Several rule operations as one change ("bundle"): checked, approved and applied together - one version,
  one nginx reload, one rollback. Uploading a rules file can propose all differences as one change; new
  rules keep their place in the file.
- Confident blocks can also cover internal sources ("external and internal, known scanners excepted");
  such a rule is never applied automatically and its sandbox test expects the internal request refused.
- A new raw rule can be placed right before a given managed rule (e.g. before 10299).
- Configuration changes by known automation (e.g. the CRS update, country lists) are recorded as
  "automation" instead of "outside" when their paths are listed.
- GeoIP: switching it on or off in Settings takes effect without a restart.
- Charts: a distribution bar is one framed track; stacked horizontal bars no longer look like two pieces.
- Consecutive button rows no longer touch.
- From an independent review: rule ids of a bundle are reserved like any other; at most 20 confident blocks
  per bundle and one pass over the access logs for all of them; every confident block of a bundle needs its
  own matching 403 test; a change whose rules would differ at apply time from the checked ones (e.g. known
  scanners changed meanwhile) is checked and approved again; the analysis refuses a model regex that could
  backtrack catastrophically before it meets any request data; known scanners must be internal and no wider
  than /16; a new LLM server address needs the API key entered again; rule comments never end in a
  backslash; many rules inserted before one rule keep their order; the sandbox's internal test address is
  never a known scanner.

## 0.3.3 (2026-11-12)

- Adoption: the root apply program also validates rule by rule (it re-checks every request itself and
  refused the 37 KB site file as a whole); a failure names the rule. Verified end to end with the first
  site's real rule files: both checks pass and the 51 managed rules are identical to the originals.
- An adoption that failed its checks can be checked again (admin).
- "This change loosens the WAF" is shown only for loosening changes, not for neutral ones such as adoption.
- The changes page opens with the list; the workflow explanation is one click away.
- Hourly chart: the total and the time are shown right at the pointer.
- Rule charts (overview, IP lookup, rules) show what a rule is: "930120 · local file access", with the rule's message.
- `doctor` / system check from the command line judge the collector by the service's recorded progress
  (no more false warning).

## 0.3.2 (2026-11-12)

- Adoption of real-sized rule files: the static check now runs rule by rule (the per-rule length limit was
  applied to the whole 37 KB file and refused the adoption); a failure names the rule.
- `@pmFromFile` / `@ipMatchFromFile` are accepted for `.data` lists inside the ModSecurity configuration
  directories (e.g. the CRS's own scanner list); any other file, a path with `..` or a URL is refused.
- Overview: coloured stat tiles with an hourly trend and the change against the previous window; active
  filters are unmistakable (highlighted bar, filled chips, a banner over the numbers); the hourly chart uses
  the full width and its crosshair follows the pointer exactly.
- Tables wider than the screen get a floating horizontal scrollbar at the bottom of the window.
- Livelier light theme: tinted page, card headers with an accent bar, tinted guides and tiles, zebra rows; the
  architecture diagram, the role cards and the WAF decision summary are coloured by meaning.
- Spacing: a notice no longer touches the page title buttons; checkboxes sit next to their explanation; flow
  step labels no longer wrap.
- GeoIP setup text says to add the [geoip] section.

## 0.3.1 (2026-11-12)

Install and upgrade
- `upgrade.sh`: checks first (installed version, no apply in progress, disk space, the release verified by the
  installed code with the pinned key, the configuration accepted by the new code), then a backup (program,
  units, configuration, database), then the switch with an explicit database migration and checks after the
  start (the service answers with the new version, program integrity, audit chain). Any failure after the
  service was stopped rolls back automatically and starts the previous version again. `--check` runs the checks
  only; `--rollback` puts back what an upgrade saved.
- New commands: `jt-waf-mgr config-check`, `migrate`, `doctor`.
- The audit trail records every change of the program version (a downgrade at priority crit).
- `tools/test_upgrade.sh`: release gate that installs the previous release in a staging root with data,
  upgrades, rolls back on an injected failure, rolls back by hand and upgrades again.

## 0.3.0 (2026-11-12)

Interface
- Every button has an icon; the site's own dropdowns and date picker replace the browser's; every list table
  can be sorted, filtered, paged and its columns chosen; light / dark / system theme; slightly larger text.
- Charts wherever there are numbers; guidance flow diagrams on the pages that are part of a process; a new
  Guide page with an interactive architecture diagram, first steps, the change workflow and the roles.
- A logo, used for the favicon, the top bar and the login page.
- The overview can be filtered (origin, outcome, site, source, rule…) by clicking values; it names the focus
  sites section.
- GeoIP: country, city and network owner (ASN) next to every external address, by-country and by-ASN charts.
- Rules files can be downloaded (current, any version, or the site's original before adoption) and uploaded:
  an upload is compared rule by rule and turned into ordinary proposals, each checked, sandboxed and approved.
- WAF decision diagram (/waf), generated from the configuration: which mechanisms block, which only score or
  log, which loosen, for external and internal sources, with the anomaly-score scale and every rule involved.
  The CRS page states the effective behaviour next to the global engine mode.
- Tablet and phone layouts: the top bar folds into a menu when the links do not fit.
- System check lists where the program, configuration, data and records are.

Security
- The root apply program no longer follows links in the service user's spool, keeps its lock and snapshots in
  its own root-only directory and restores from memory (a compromised service could otherwise have reached
  root or written unchecked directives into nginx).
- An apply is refused when a managed file was edited outside jt-waf-mgr, instead of silently overwriting the
  edit; an approver can explicitly restore the files. A failed apply keeps its version number in the history.
- Login: at most four scrypt checks at once, atomic failure counting, IPv6 limits per /64, wrong current
  passwords on "change password" count toward the lockout; invalid Content-Length is refused.
- The creator of an API token cannot approve changes proposed through it.
- systemd: the web service and the apply program may only talk to the loopback; the apply program can write only
  /etc/nginx, its state directory and the spool.
- Syslog audit lines carry `"severity": "crit"` for integrity alerts (files drop the syslog priority).
- Draft Wazuh rules for the audit lines (deploy/wazuh).
- Collector: redaction runs in linear time on clipped input (one long parameter used to stall the collector for
  seconds to hours); oversized records are kept as truncated events instead of being dropped; long transaction
  ids no longer collide; every cookie and the Authorization / Cookie headers are always masked; copytruncate
  rotation no longer loses lines; one bad record no longer blocks the rest.
- Evidence checks use ModSecurity's own decoding (`+`, %u, path normalisation) and no longer skip DAV paths,
  so a block that would hit real traffic cannot pass (or be auto-applied); regression samples need several
  distinct sources and skip catch-all hosts and paths with WAF events.
- Integrity: the append-only triggers are compared word for word; a purge beyond the retention period (or any
  purge when keeping forever) is reported; the whole program directory is checked (a module shadowing the
  standard library, bytecode caches and links are found); upgrades are verified with the installed code.
- GeoIP reader: bounded decoding work per lookup and type checks on every value.

## 0.2.1 (2026-11-12)

- The interface uses a plain "/" instead of the full-width slash in Chinese and Japanese texts; the
  i18n check now rejects the full-width slash.
- The incremental and the daily full audit-chain checks no longer write two identical anchors when they
  fall due together.
- The installer and the compliance guide explain how to set the append-only flag on the anchor file
  from the host when jt-waf-mgr runs in a container (LXC).

## 0.2.0 (2026-11-11)

The change workflow.

- Adoption: the existing site rule files become jt-waf-mgr managed files, rule for rule (verified by a
  decision-equivalence sandbox run: the same requests give the same results before and after).
- Templates: exclusion (narrowest scope; remove a target, a rule, a tag; score only; body parser),
  confident block (external sources only, decided by CRS's 949110), redaction (not inspected, never
  logged), plugin toggle, and expert raw rules (admin only, forbidden-directive list).
- Static checks (regex sanity, too broad, ReDoS shape and runtime test, id ranges, never reused ids).
- Evidence: access-log scan for confident blocks (external 2xx/3xx, internal hits), alert impact for
  exclusions; an override needs a written justification and is never auto-applied.
- Sandbox: a throwaway nginx with the production configuration plus the change; user test cases,
  encoding / case / slash variants, internal-source check, per-site regression samples.
- Approval: proposer cannot approve (single-admin mode with OTP for one's own loosening); loosening
  always needs a person; optional auto-apply for qualifying tightening with a daily limit.
- Root apply program (systemd path unit): validates again, snapshot, nginx -t, reload, verifies new
  workers, waits for old ones, health check before/after, automatic restore on any failure;
  manual-edit detection; versions and one-click rollback.

Integrity and compliance:

- Audit trail hash chain (sha256 of the previous hash and the canonical row), append-only table
  (triggers), retention purge that keeps the chain verifiable; anchors every 5 minutes in an
  append-only file (chattr +a) and in syslog; every syslog line carries the row's id and hash;
  verification incremental / daily / on demand; NDJSON export with hashes, verifiable offline.
- Signed releases: release/MANIFEST.sha256 (every file) signed with the release key (RSA-3072); the
  installer verifies before installing and pins the key; the service (hourly) and the root apply
  program (every run, refusing on failure) check the installed files, units and wrapper;
  `jt-waf-mgr verify-release` before upgrades; CycloneDX SBOM.
- Configuration fingerprints (nginx / ModSecurity / CRS files, nginx binary, module) every 5 minutes;
  each change recorded and attributed (jt-waf-mgr or outside).
- Accounts: password character classes, history, optional maximum / minimum age; account expiry;
  dormant accounts disabled; session limit; own sessions list; sign out everywhere; previous sign-in
  and failed attempts shown after sign-in; login notice; account review export; lockouts audited
  as critical.
- Daily database backup with integrity check and SHA-256, verification on demand.
- System check page (program integrity, audit chain, anchors, syslog, time sync, disk, database,
  backups, collector, apply program, configuration changes, accounts, web settings) and Compliance
  page (ISO/IEC 27001:2022, Taiwan Cyber Security Management Act baseline, OWASP Top 10:2025),
  computed from the live configuration. docs/COMPLIANCE.md, SECURITY.md.
- Every write API route audits (enforced by a test); denied approvals and rollbacks are audited; the
  OTP for approving one's own loosening is replay-protected.

## 0.1.0 (unreleased)

First version: read-only.

- ModSecurity v3 JSON audit log collector with rotation handling and sensitive-field masking.
- Overview, events, event detail, rules, sites, CRS status, IP lookup.
- Local accounts with TOTP, roles, API tokens with scopes, audit trail to database and syslog.
- Read-only API: status, overview, events (filters, stats, NDJSON export with cursor and SHA-256),
  rules, removals, sites, CRS, IP lookup.
- UI in English, Traditional Chinese (Taiwan) and Japanese.
- Offline installer with a hardened systemd unit; no third-party Python packages.
