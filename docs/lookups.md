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
| All tables together | 256 MB |

Tables are kept in memory for searches, which is what the limits protect.

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
