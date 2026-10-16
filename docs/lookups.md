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
4. Select **Add table**.

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

Matching is exact, case included: `WEB-01` does not match `web-01`. Use
`eval host=lower(host)` before `lookup` when the case differs. An event whose field
is missing or empty, or that matches no row, is left as it is.

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

## The inputlookup command

`inputlookup` starts a search with the rows of a table instead of events, to
check a table or report on it:

```
| inputlookup owners
| stats count by team
```

`max=N` reads at most N rows (`| inputlookup max=50 owners`); without it a
search reads up to the event limit (`search.max_events`, 10,000 by default).
It must come first, with nothing before the `|`. An empty cell is a missing
field, so `where isnull(owner)` finds rows with no owner.

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
1 GB, or a database of another kind (such as ASN) is not used, and the server log
says why while searches keep the file they had.

## Several servers

Each server keeps its tables in `tables` inside the folder of the asset and
identity lists (`lookups.dir`). They are not yet shared between the servers of a
cluster, so while there is more than one server, **Settings > Lookups** shows the
tables but cannot change them, and the API answers changes with `409 Conflict`.

## API

| Route | Role | What it does |
| --- | --- | --- |
| `GET /api/lookuptables` | viewer | Lists the tables: name, columns, rows, bytes, last change |
| `GET /api/lookuptables/{name}` | viewer | One table and its first 1,000 rows |
| `GET /api/lookuptables/{name}.csv` | viewer | The whole table as CSV |
| `PUT /api/lookuptables/{name}` | admin | Adds or replaces a table; the body is the CSV file |
| `DELETE /api/lookuptables/{name}` | admin | Deletes a table |

API tokens can only read, so changes come from a signed-in admin.
