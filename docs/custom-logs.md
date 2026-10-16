---
description: Bring in a log Signalith has no parser for. Paste a sample, check the suggested parser, see which detections can use it, and save it for agents and syslog.
---

# Any other log

Signalith reads Windows, Linux, cloud, antivirus and many network logs on its own. For
a log it does not know (an in-house application, a firewall without a built-in parser, a
CSV export), an admin can show it a sample and save a **custom parser**. Signalith then
reads that log into the same data models as everything else, so searches, dashboards
and detections use it.

## Make a parser

1. Open **Add data** and pick **Any other log**.
2. Paste ten to fifty lines of the log, or upload a file. Signalith reads the first 500
   lines, up to 512 KB. The sample stays on the server unless you ask the AI model for
   help (below).
3. Select **Read the sample**. Signalith works out:
    - the **format**: JSON (one object per line, or an array, or pretty-printed),
      key=value, CSV with or without a header row, CEF, LEEF, or free text, for which it
      writes a regular expression;
    - a **syslog header** before each line, when there is one;
    - the **event time** and how it is written, including a date and a time in two
      fields (`date=… time=…`);
    - a **data model** (Authentication, Network_Traffic, Web, and so on) and a
      **sourcetype** for searches, such as `fortinet:fortigate`;
    - which fields mean a data model field, such as `srcip` → `src` or `user.name` →
      `user`.
4. Check the suggestion. Every change previews at once: the fields found, an example of
   each, and the first events as they would be stored. Use **Stored as** on a field to
   map it to a data model field; Signalith suggests one where a name looks like one.
5. **Detections that can use it** shows how many detections of that data model can run
   on these events, which ones the sample already matches, and which fields to map so
   more can run.
6. Name the parser and select **Save parser**. Every server uses it at once. Events
   already stored keep the fields they had.

Parsers are listed above the steps, where you can edit, delete or search the events of
each one.

### What the options mean

| Option | What it does |
| --- | --- |
| Format | How the body of a line is read. **Text only** keeps the line as the message, with the syslog header's fields. |
| Lines start with a syslog header | Reads the time, host and program from an RFC 3164 or RFC 5424 header, then the rest of the line in the format. |
| Event time, Written as | The field that holds the time, and its format. Without one, events take the time they arrive. A time with no year (`Oct 16 14:05:09`) takes this year, or last year when that would put it more than two days ahead. |
| Use the data model's action words | Turns `accept`, `deny`, `failed` and the like into the data model's `allowed`, `blocked`, `success` or `failure`. The original stays in `vendor_action`. |
| Product | Fills `vendor_product`. |
| Also read syslog from | Syslog program names (the `APP-NAME` or tag in the header). Messages from them are read with this parser. |

Time formats Signalith reads: ISO 8601 (`2026-10-16T14:05:09Z`, or with a space),
`2026/10/16 14:05:09`, Apache's `16/Oct/2026:14:05:09 +0000`, US `10/16/2026 14:05:09`
(with or without AM/PM), RFC 1123, syslog's `Oct 16 14:05:09`, `Fri Oct 16 14:05:09 2026`,
and Unix time in seconds or milliseconds. A time without a zone is read as UTC.

### Regular expressions

Free text is read with a regular expression whose **named groups** become fields:

```text
^(?P<timestamp>\S+ \S+) (?P<severity>\w+) \[auth\] login (?P<action>\w+) user=(?P<user>\S+) src=(?P<src>\S+)
```

Name groups after data model fields where you can (`user`, `src`, `dest`, `action`). The
expression is [RE2](https://github.com/google/re2/wiki/Syntax): matching takes time in
proportion to the line and never backtracks, so a pattern cannot stall ingest. RE2 has no
look-ahead or back-references. A pattern can compile to at most 500 instructions, with
counted repeats such as `{1,20}` up to 100, and reads at most the first 8 KB of a line (2 KB of a syslog message), so
what one line costs stays small. A line the pattern does not match is still stored, as
text, and found by searching for its words.

## Improve it with AI

When an AI model is set up under **Settings → AI assistant** (see [Investigate with AI](investigate.md)), **Improve with AI** asks it to suggest a
better parser, for free text especially. Before you select it, the page says which model
it uses and where it sends the request. Signalith sends only the first 20 lines of the
sample (at most 8 KB), the current parser, and the list of data models and formats.
Credentials in those lines (password, token, API key, cookie, session ID and
Authorization values) are replaced with `[masked]` first. The lines go as a JSON list of
strings, and the model is told they are data to describe, not instructions to follow,
since whoever writes to the log can put any text in them. Still compare the field
mappings with the sample before you save: a crafted log line could try to steer them.

The model's answer goes through the same checks as a parser you write, and its regular
expression must read at least half the sample lines; one that does not is sent back
once with the problem. The page shows what the model changed, and nothing is saved until
you save it. Each request is written to the audit log: who sent it, how many lines, and
to which model and address.

Without a model, Signalith uses its own rules, which work offline.

## Send the log

Step 5 of the page shows how, once the parser is saved:

- **Files on Linux or Windows**: enter the log files (one per line; `*` matches any part
  of a name) and select **Make the agent input**. Add the `[INPUT]` section it shows to
  the agent's `fluent-bit.conf`, next to its other inputs, and restart Fluent Bit. Set up
  the agent from the Linux or Windows card first if the host has none. The input sends
  each line under the tag `custom.<parser name>`, from the end of the files onward.
- **Syslog**: name the device's program under **Also read syslog from**, and point the
  device at Signalith as on the [Syslog](sending-data.md) card. A program Signalith already
  reads (sshd, sudo, firewalls and the like) keeps its built-in parser, and the host,
  facility and severity always come from the syslog header.
- **A script**: send JSON lines to `/api/ingest` with an [agent token](agent-tokens.md)
  and the header `X-Signalith-Tag: custom.<parser name>`. Each line is
  `{"log": "<the line>"}`, or, for a JSON parser, the JSON object itself.

Lines that arrive under a parser's tag after it is deleted are stored as plain text.

## Where parsers are kept

A server on its own keeps its parsers in `custom-parsers.json` in its state folder. In a
[cluster](multi-server.md) they are part of the shared settings, so every server reads
alike, whichever one an agent sends to; a server that founds or joins a cluster brings
its parsers along, and the cluster's own win where both have one of a name.
`signalith cluster export` writes them back as the file.

## Limits and checks

Only admins can read samples, save or delete parsers, or ask the AI model, since a parser
changes how events are stored. Saving, changing and deleting a parser are written to the
[audit log](audit.md).

| Limit | |
| --- | --- |
| Parsers | 100 |
| Sample | 500 lines, 512 KB |
| Line read | 16 KB (the whole line is still stored) |
| Regular expression | 2,000 characters, 150 named groups, 500 compiled instructions, repeats up to 100, first 8 KB of a line |
| CSV columns, field mappings | 128 each |
| Syslog programs per parser | 16 |
| Files per agent input | 8, absolute paths without `..`, commas, quotes or shell characters, and none that hold secrets: the agent's and Signalith's own folders, `/etc/shadow`, `/etc/sudoers`, SSH and private key folders, `*.key`, `*.pfx`, the Windows registry hives |

Field names must be valid Signalith field names, and a parser cannot write the fields
Signalith sets itself (`datamodel`, `@timestamp`, risk fields and the like). A parser that
fails on a record leaves it to the built-in parsers, so one bad line cannot fail a batch.

## API

| Route | |
| --- | --- |
| `GET /api/parsers` | The saved parsers, formats, data models, time formats and limits. |
| `POST /api/parsers/analyze` | `{"sample": "…"}` suggests a parser; with `"parser"`, previews that one. Returns the parser, the preview and the detections. |
| `POST /api/parsers/refine` | `{"sample", "parser"}`: asks the AI model to improve the parser. |
| `PUT /api/parsers/{name}` | Saves a parser. |
| `DELETE /api/parsers/{name}` | Deletes it. |
| `GET /api/parsers/{name}/input?os=linux&paths=…` | The agent input for log files (paths separated by newlines). |
