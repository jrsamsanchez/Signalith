# Splunk SPL compatibility

Signalith's query language is pipe-based, like Splunk's SPL, so most searches an SPL user
writes run as they are. This page lists what is supported, what works differently and what
is missing, so you know before you type. Signalith is not affiliated with Splunk; SPL is
named here only to describe compatibility.

## What "94%" means

Signalith runs every search from Splunk's open `security_content` detections, baselines and
dashboards (2,223 searches) in its tests. **2,089 of them (94.0%) are accepted**: they parse
and run without an error. That number does not prove they give the same rows as in Splunk.

A second test checks results. It runs 122 searches over a fixed set of events and compares
the rows with the ones Splunk gives. It covers stats over missing values, multivalue fields,
`search` and `where`, sorting, time snapping, `dedup`, `top`, `eventstats`, `streamstats`,
`join` and `transaction`. Every difference it found has been fixed or is listed under
[Works differently](#works-differently).

## Commands

Every command below is supported. Notes on how some of them work differently follow the
lists.

- **Search and filter:** `search`, `where`, `regex`, `dedup`, `head`, `tail`, `uniq`,
  `from`, `multisearch`, `union`, `set`, `format`, `return`
- **Statistics:** `stats`, `eventstats`, `streamstats`, `timechart`, `chart`, `top`, `rare`,
  `tstats`, `bin`, `bucket`, `fieldsummary`, `contingency`, `concurrency`, `trendline`,
  `predict`, `outlier`, `anomalydetection`, `correlate`, `kmeans`, `cluster`, `geostats`,
  `eventcount`, `timewrap`, `makecontinuous`
- **Fields:** `eval`, `rex`, `extract`, `xmlkv`, `xpath`, `spath`, `fromjson`, `rename`,
  `table`, `fields`, `fillnull`, `filldown`, `convert`, `fieldformat`, `replace`, `strcat`,
  `rangemap`, `foreach`, `setfields`, `addinfo`, `accum`, `delta`, `autoregress`,
  `iplocation`, `highlight`, `abstract`
- **Multivalue:** `mvexpand`, `makemv`, `nomv`, `mvcombine`
- **Reshape:** `sort`, `reverse`, `transpose`, `xyseries`, `untable`, `addtotals`,
  `addcoltotals`, `gauge`
- **Combine:** `append`, `appendpipe`, `join`, `transaction`, `map`
- **Lookups and threat intel:** `lookup`, `inputlookup`, `outputlookup`, `enrich`, `intel`,
  `threatmatch`
- **Generate:** `makeresults`

### Works differently

| What | In Signalith |
| --- | --- |
| Plain `where` comparisons | `where user="bob"` ignores case, as a search term does, so it can run in OpenSearch. Splunk's `where` is case-sensitive. As soon as the condition uses a function or arithmetic it is case-sensitive, as in Splunk |
| A bare name on the right of `where` | Right after the search, only a field a data model names is read as a field; other names are compared as text. Use a single-quoted name, as in `where a > 'b'`, to always compare two fields |
| `timechart` | Must come before other commands that change the results, such as `eval` or `stats`; it runs in OpenSearch |
| `stats` over many groups | Up to 50,000 groups are counted exactly; past that OpenSearch ranks them and the result says so |
| `dc()`, `median()`, `perc95()` | Estimated by OpenSearch on large data; exact when `stats` runs in Signalith |
| `values()` | Up to 100 values when `stats` runs in OpenSearch, 10,000 in Signalith; a result that leaves values out is marked truncated |
| `stats sum(bytes*)`, `values(*) as *` | Supported in `stats` and `eventstats`, which then run in Signalith over at most `search.max_events` events. `timechart`, `chart`, `streamstats`, `tstats` and `by` refuse `*` field names |
| `streamstats` | Takes `count`, `dc`, `sum`, `avg`, `min`, `max`, `range`, `first` and `last`; `time_window=`, `reset_on_change=` and `global=` are missing |
| Commands that need every event (`eval` before `stats`, `dedup`, `transaction` and so on) | Run in Signalith over at most `search.max_events` events. A result that saw fewer events than matched is marked sampled |
| Time zone | The Search page uses your browser's time zone; detections and dashboards use UTC |
| `strftime` | `%Q` (milliseconds) is missing |

### Missing

`appendcols`, `multikv`, `erex`, `collect`, `loadjob`, `savedsearch`, `rest`, `metadata`,
`selfjoin`, `gentimes`, `inputcsv`, `outputcsv`, `mstats`, `sistats` and the other summary
indexing commands, and search macros (`` `macro` ``). Signalith has its own
[summary indexes](summaries.md) and saved searches.

## Stats functions

Supported in `stats`, `eventstats`, `timechart` and `chart`: `count`, `dc`
(`distinct_count`), `sum`, `avg` (`mean`), `min`, `max`, `median`, `perc1` to `perc99`
(`p95` too), `stdev`, `stdevp`, `var`, `varp`, `sumsq`, `range`, `mode`, `values`, `list`,
`first`, `last`, `earliest`, `latest`, and any of them over `eval(...)`.

Missing: `estdc`, `exactperc`, `upperperc`, `earliest_time`, `latest_time`, `rate`,
`per_second`, `per_minute`, `per_hour` and `per_day`.

## Eval functions

- **Conditions and tests:** `if`, `case`, `coalesce`, `nullif`, `null`, `true`, `false`,
  `validate`, `isnull`, `isnotnull`, `isnum`, `isint`, `isstr`, `isbool`, `typeof`, `in`,
  `like`, `match`, `cidrmatch`
- **Text:** `len`, `lower`, `upper`, `substr`, `replace`, `trim`, `ltrim`, `rtrim`,
  `urldecode`, `printf`, `split`, `md5`, `sha1`, `sha256`, `sha512`
- **Numbers:** `abs`, `ceil`, `ceiling`, `floor`, `round`, `sqrt`, `pow`, `exp`, `ln`,
  `log`, `min`, `max`, `pi`, `random`, `exact`, `sin`, `cos`, `tan`, `asin`, `acos`, `atan`,
  `atan2`, `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, `atanh`, `hypot`, `bit_and`, `bit_or`,
  `bit_xor`, `bit_not`, `bit_shift_left`, `bit_shift_right`
- **Conversion:** `tonumber`, `tostring`, `ipmask`
- **Multivalue:** `mvappend`, `mvcount`, `mvdedup`, `mvfilter`, `mvfind`, `mvindex`,
  `mvjoin`, `mvmap`, `mvrange`, `mvsort`, `mvzip`
- **JSON:** `spath`, `json_extract`, `json_keys`, `json_valid`, `json_array_to_mv`,
  `json_object`, `json_array`
- **Time:** `now`, `time`, `strftime`, `strptime`, `relative_time`

Missing: `searchmatch`, `sigfig`, `lookup`, `json_set`, `json_append`, `json_extend`,
`mv_to_json_array` and `tojson`.

## Time modifiers

`earliest=` and `latest=` take what Splunk takes: relative times such as `-24h` or `-7d@d`,
chained ones such as `@d-1h`, snaps to `@s`, `@m`, `@h`, `@d`, `@w` (Sunday, or `@w0` to
`@w6`), `@mon`, `@q` and `@y`, `now`, epoch seconds, and dates such as `2026-10-01` or
`10/01/2026:00:00:00`. A time that cannot be read is an error, not an empty result.

See the [query language](query-language.md) for how each command and function works.
