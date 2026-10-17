# Lookup tables

A lookup table is a CSV file of your own that searches and detections add columns
from. For example, a list of who owns each server:

```csv
host,owner,team
web-01,Ana Ruiz,Web
db-01,Sam Lee,Data
```

uploaded as `owners`, lets any search add the owner and team of each event's host:

```
datamodel=Authentication action=failure
| stats count by host
| lookup owners host OUTPUT owner, team
```

Lookup tables are for your own reference data: service owners, cost centers,
known-good software, VPN address ranges by site, user departments from an HR
export. The [asset and identity lists](https://github.com/jrsamsanchez/signalith/blob/main/docs/query-language.md#commands)
(the `enrich` command and risk scoring) stay the place for host priority and user
watchlists.

## Adding a table

Admins add tables on **Settings > Lookups**:

1. Select **Add a table**.
2. Pick the CSV file. Its first line names the columns.
3. Check the name (taken from the file name). Searches use this name, so it is
   lower-case letters, digits, `-` and `_`.
4. Optionally, under **Matching**, name the **Wildcard columns** and turn on
   **Ignore case** (see [Wildcards and case](#wildcards-and-case)).
5. Select **Add table**.

Searches and detections use the table right away. **Replace…** in a table's menu
uploads a new file over all its rows, **View** shows the first rows, **Download
CSV** gets the whole table back, and **Delete** removes it. A search that looks up
a deleted table fails with an error that names it, so check your detections first.

Every add, replace and delete is in the audit log (`lookup table saved`,
`lookup table deleted`) with who did it.

### The CSV file

- The first line names the columns. Names are kept as written (case included) and
  must be different from each other.
- Spaces around values are dropped. A row may have fewer values than there are
  columns (the rest are empty) but not more.
- A file saved by Excel works, including its byte order mark.
- Downloaded tables prefix cells that a spreadsheet would run as a formula (such as
  `=1+1`) with `'`, so opening the download is safe.

### Limits

| | Limit |
| --- | --- |
| One file | 16 MB |
| Rows in one table | 1,000,000 |
| Columns in one table | 100 |
| Tables | 200 |
| One table in memory | 64 MB |
| All tables together, in memory | 256 MB |

Tables are kept in memory for searches, which is what the limits protect. A table
takes more memory than its file, about 16 bytes more for each cell, so a table of
many short or empty cells reaches the memory limits first. The values `lookup` and
`join` add to results count toward the search's memory budget, as `eval`'s do.

Every user who can search can read every table, with `inputlookup` or by
downloading it, so keep secrets out of them.

## The lookup command

```
lookup <table> <column> [AS <field>] [, ...] [OUTPUT | OUTPUTNEW <column> [AS <field>], ...]
```

- `<column>` is the table column to match. When the events' field has another
  name, add `AS <field>`: `lookup owners host AS dest`.
- Several key columns must all match: `lookup ports port, protocol AS transport`.
- `OUTPUT` names the columns to add, each optionally under another name:
  `OUTPUT owner, team AS owner_team`. Without `OUTPUT` every other column is added.
- `OUTPUTNEW` adds only fields an event does not have already. `OUTPUT` replaces
  them.

Matching is exact, case included, unless the table says otherwise (see
[Wildcards and case](#wildcards-and-case)): `WEB-01` does not match `web-01`. An
event whose field is missing or empty, or that matches no row, is left as it is.

`local=true` and `update=true` before the table name are accepted for searches
written for Splunk and change nothing: tables are on the server that runs the
search and always current.

When several rows match, each added field holds the values of all of them (up to
100). A multivalue field, such as one from `rex max_match=0`, looks up each of its
values.

`lookup` runs on the results in the server, so it works anywhere in a query: on
events, after `stats`, and in detections.

```
* | lookup vpn_sites src_ip AS src OUTPUT site
| stats count by site
```

```
datamodel=Endpoint
| lookup approved_software process_name OUTPUTNEW approved
| where isnull(approved)
```

### Wildcards and case

A table can match like Splunk's `match_type = WILDCARD(<column>)` and
`case_sensitive_match = false`, which many published detections' lookups need:

- In a **wildcard column**, `*` in a cell matches any text, including none:
  `*\psexec*.exe` matches `C:\Tools\PsExec64.exe` (with **Ignore case**). A
  cell without `*` still matches exactly. Every other character, `?` included,
  matches itself.
- **Ignore case** makes every key column match whatever the case.

Rows without patterns are found at once; rows with patterns are tried one by one
for each event, in table order and after the exact matches, so a table of many
thousand patterns makes searches slower. Each try counts toward the search's work
limit.

Set both when adding or replacing the table. Replacing a table sets them again
from the form, which starts with the table's current choices.

## The inputlookup command

`inputlookup` starts a search with the rows of a table instead of events, to
check a table or report on it:

```
| inputlookup owners
| stats count by team
```

`max=N` reads at most N rows (`| inputlookup max=50 owners`); without it a
search reads up to the event limit (`search.max_events`, 10,000 by default).
It must come first, with nothing before the `|`, unless it has `append=true`
(`| inputlookup append=true owners`), which adds the table's rows after the
rows the search has so far. An empty cell is a missing
field, so `where isnull(owner)` finds rows with no owner.

## The outputlookup command

`outputlookup` writes a search's rows to a table and passes them on, to keep
a list a search builds, such as the users seen this week:

```
index=signalith-authentication-* earliest=-7d
| stats count by user
| outputlookup weekly_users
```

Only admins can use it, and it writes only when they press **Run** (or
Ctrl+Enter) on the Search page. Changing the time range, sorting, filtering
on a value, drilling down or opening the Events tab runs the search again
without writing, and so does the Ask box. Detections cannot use it (a
detection with it is refused when saved), nor can dashboards, the AI tools or
API tokens. Each table written is in the audit log, with who wrote it and how
many rows. Through the API, a search writes only with `"write_lookups": true`
in its request.

A table that exists is never replaced by accident. Without `append=`, the
command makes a new table and fails if one by that name exists; `append=t`
adds the rows after the table's own (new fields become new columns), and
`append=f` replaces the table. The table keeps its wildcard and case
settings. The same limits apply as to an upload. Every field is written except
those starting with `_`, apart from `_time`; a multivalue field is written as
its values on separate lines.

`max=N` writes at most N rows. With no rows, `create_empty=f` makes no new
table, and `override_if_empty=f` leaves a table `append=f` would replace as
it is. A name may end in `.csv`, which is dropped. Like uploads, it is refused
while several servers share the data.

## GeoIP database for iplocation

The search command `iplocation` adds where an IP address is (`City`, `Region`,
`Country`, `lat`, `lon`) from a GeoIP database in the MaxMind DB format (`.mmdb`).
Signalith does not ship one, since the free ones need an account or a credit line,
so an admin adds it. Any City or Country database works, free or paid:

- **DB-IP IP to City Lite**: free under CC BY 4.0, no account. Download the MMDB
  file from <https://db-ip.com/db/download/ip-to-city-lite> and unzip it (`.gz`).
  The license asks that pages showing its results credit DB-IP, for example
  "IP geolocation by DB-IP".
- **MaxMind GeoLite2 City**: free with a MaxMind account, at <https://www.maxmind.com/en/geolite2/signup>.

Put the `.mmdb` file in the `geoip` folder inside the lookups folder on **each
server** (the files are not shared between servers):

| Install | Folder |
| --- | --- |
| Docker | `/var/lib/signalith/lookups/geoip`: `docker compose -f deploy/docker/docker-compose.yml cp dbip-city-lite.mmdb signalith:/var/lib/signalith/lookups/geoip/` |
| Linux package or install script | `/var/lib/signalith/lookups/geoip` |
| Windows, or a `lookups.dir` of your own | `geoip` inside the lookups folder (`lookups.dir`) |

No restart is needed: the next `iplocation` search reads the file. Signalith uses
the newest `.mmdb` file in the folder and looks for a newer one every 30 seconds,
so to update it, add the new file and then delete the old one. The file is read
into memory (about 130 MB for a City database, 10 MB for a Country one) the first
time a search uses it, and is checked before use; a damaged file, one larger than
512 MB, or a database of another kind (such as ASN) is not used, and the server log
says why while searches keep the file they had.

## Tables that come with content packs

Some [Splunk Security Content](detections.md#splunk-security-content) rules look
values up in a table Splunk publishes with them: known named pipes of remote access
tools, PowerShell attack strings, vulnerable drivers and the like. The Splunk pack
ships those tables (`internal/detect/packs/splunk/lookups`), each as
security_content has it: the CSV and the yml that says how it matches. Only tables
that a shipped rule reads are included.

A pack's table is named after its pack: `browser_app_list` in security_content is
`splunk-browser_app_list` in Signalith, and the converted rules look up that name.
So a table of yours named `browser_app_list` stays yours, and a pack update never
replaces it, nor does your table change what a pack rule finds. Names starting with
`splunk-` are kept for the pack's tables: adding a table with such a name is
refused. (A table of yours saved under such a name before is hidden by the pack's
table of the same name, and is not listed; rename its file in the tables folder.)

Pack tables:

- are kept in memory with the pack, not in the tables folder, and don't count
  toward the [limits](#limits) on your tables;
- are not listed on **Settings > Lookups**, which lists your own tables, but
  searches can read them like any table (`| inputlookup splunk-loldrivers`), and
  `GET /api/lookuptables/splunk-loldrivers` shows one, with `"pack": "splunk"`;
- can't be replaced or deleted; a [content update](detections.md#content-updates)
  that brings new rules brings their tables too.

Each table's yml settings are kept: `match_type: WILDCARD(<column>)` makes a
[wildcard column](#wildcards-and-case), `case_sensitive_match: false` ignores case,
and `min_matches: 1` with `default_match` fills the output fields of an event no
row matches. `max_matches: 1` keeps the first matching row in the table's order, as
Splunk does; a rule whose table has a row with a pattern before a row without one
that it also matches is left out, since Signalith tries the rows without patterns
first. A rule is left out too when its table's settings, or how its later stages
read the output, could give a different result than in Splunk, for example a table
with spaces around values (Splunk keeps them; Signalith's CSV reading drops them),
or an output compared with a value while several rows may match. The pack's
`REPORT.md` lists each rule left out and why.

## Several servers

Each server keeps its tables in `tables` inside the folder of the asset and
identity lists (`lookups.dir`). They are not yet shared between the servers of a
cluster, so while there is more than one server, **Settings > Lookups** shows the
tables but cannot change them, and the API answers changes with `409 Conflict`.

## API

| Route | Role | What it does |
| --- | --- | --- |
| `GET /api/lookuptables` | viewer | Lists the tables: name, columns, rows, bytes, last change, and `wildcard` and `ignore_case` when set. [Content packs' tables](#tables-that-come-with-content-packs) are not listed |
| `GET /api/lookuptables/{name}` | viewer | One table and its first 1,000 rows; a content pack's table has `pack` set |
| `GET /api/lookuptables/{name}.csv` | viewer | The whole table as CSV |
| `PUT /api/lookuptables/{name}` | admin | Adds or replaces a table; the body is the CSV file. `?wildcard=col1,col2` names wildcard columns and `?case_sensitive=false` ignores case; without them the table matches exactly |
| `DELETE /api/lookuptables/{name}` | admin | Deletes a table (not a content pack's) |

API tokens can only read, so changes come from a signed-in admin.
