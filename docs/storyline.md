# Attack storyline

The **Attack storyline** page shows everything Signalith knows about one intrusion as a
single story. Instead of twenty separate findings about the same laptop, an analyst sees
when the attack started, which ATT&CK tactics it reached and in what order, and which
accounts, systems, addresses and processes tie it together.

## Opening a storyline

- **From a finding:** **Attack storyline** next to the finding's entities (or in **More
  actions**). The story follows the finding's users, systems and addresses, from three days
  before the finding to one day after it.
- **From an investigation:** **Storyline** at the top of the case. The story follows the
  case's entities and those of its findings, around the times of its findings.
- **From the Risk page:** **Storyline** in a user's or system's details.
- **From Assets & identities:** select a host or an identity in either list.
- **By name:** open **Monitor > Attack storyline**, type a user, host or IP address and pick
  the last 24 hours, 7 days or 30 days.

The address of the page names the story (for example `#storyline?type=user&object=alice`),
so it can be bookmarked or sent to a colleague, who sees it with their own role.

## What it shows

- **Kill chain:** every ATT&CK tactic in the order attacks usually move through them, lit
  where the story reached it and coloured by its most urgent finding. Select a lit tactic
  to show only its items.
- **Timeline:** one lane per tactic reached, with a mark for each finding (coloured by
  urgency) and risk event (a diamond). The dashed line joins the first item of each tactic,
  so you can see how the attack moved. Below it, the findings and risk events themselves,
  grouped **By tactic** or listed **By time**. Select a finding to open it.
- **Who and what:** the users, systems, addresses and processes in the story, linked by the
  findings they share and by the activity between them. Followed entities have a ring.
  Select one to see its asset or identity context and to **Follow this** (build its own
  storyline) or **Search events** about it.
- **Activity that links them:** the busiest sign-ins, process starts and connections between
  those entities, each with **Open in Search**:
    - sign-ins (Authentication) by the story's users, to its systems, or from its addresses;
    - process starts (Endpoint) on its systems, of the processes its findings name, with
      their parent processes, which draws the process tree;
    - connections (Network_Traffic) to or from the addresses its findings name.

Risk events that a detection wrote together with a finding add to that finding; risk-only
detections appear as their own items.

## Opening an investigation

Analysts and admins can select **Open an investigation** to open a case holding every
finding in the story, with the followed entities and a description of the tactics reached.
Findings already in another case stay there. From a case's own storyline, the button goes
back to the case.

## Limits

A storyline only reads, and only what the person's role can already see on the Findings,
Risk and Search pages: every role may open it. To keep it quick on a busy server it reads at
most:

| What | Limit |
|---|---|
| Time range | 31 days |
| Entities followed | 8 |
| Findings | 200 |
| Risk events | 300 |
| Sign-ins, process starts and connections | 40 rows of each |
| Entities and links shown | 60 entities, 120 links |

When a story reaches a limit, the page says what it left out; a shorter time range shows
everything. Its searches count against the person's share of the search slots, like any
other search. Values with wildcards (`*`, `?`) are not accepted, so a storyline always
looks for exact values.

The API is `GET /api/storyline` with `type` (`user`, `system` or `ip`), `object` and
`since` (up to `31d`), or with `finding` or `case` and an ID.
