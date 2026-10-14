# Playbooks

A playbook does the first steps for you when a detection raises a finding: tell the team,
block the address once an analyst approves it, open a case, set the finding to In progress.
Set playbooks up on the **Playbooks** page, under Detect & respond. Only admins see that page.
Analysts approve or reject the steps that wait for them on the **Approvals** page, under
Monitor.

A playbook has three parts:

- **When**: the detections it starts for (any detection, or only some) and the least
  urgency, such as "high or above".
- **Then**: the steps, in order.
- **Ask for approval in**: an optional notification channel that is told when a step
  waits for approval.

The page sums each playbook up in one sentence, for example:

> When brute-force fires at high or above: notify Slack #soc, then block IP on the edge
> firewall for the source IP after approval, then open a case (or add to the one it
> opened), then set the finding to In progress.

A playbook runs **once per finding**. It starts for findings raised after it was added
or turned on, never for older ones, so turning a playbook on does not replay last week's
findings. Findings from the one-click [sample data](sample-data.md) are skipped unless
**Include sample data** (under **More options**) is on. With it on, the steps still really
run, so a sample finding can block a real address or send a real message.

## Steps

| Step | What it does |
| --- | --- |
| **Notify a channel** | Sends the finding to one [notification channel](notifications.md), as a rule would. It does not wait for the notification rules: it sends even when no rule matches, and a rule that also matches sends its own message too. |
| **Run a response action** | Runs one [response action](response-actions.md) on a target taken from the finding. See below. |
| **Open a case** | Opens an [investigation](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#investigations) with the finding in it. The title may use `{title}` `{detection}` `{urgency}` `{src}` `{dest}` `{user}` `{host}` `{finding_id}` (it is the finding's title when left empty), and an owner may be set. With **Add later findings to the case this playbook opened** on, a later finding goes into the last case this playbook opened while that case is still open, instead of opening another one. |
| **Set the finding** | Sets the finding's status, its owner, or both. |

A playbook has at most 20 steps, and a server at most 100 playbooks.

### Response actions in a playbook

Pick the action and its **target**:

- **Source**, **Destination**, **User** or **Host**: the finding's `src`, `dest`, `user`
  or `host` entity.
- **First entity that fits**: the first of the finding's entities the action can act on
  (an IP for an IP action, a user for a user action, and so on).
- **A fixed value**: always the same target, such as a webhook that takes no target, or a
  quarantine group.

The target is checked exactly as when an analyst runs the action by hand. If the finding
has no such value, or it is not the right kind (a user name for an IP action), the step
fails and the playbook stops.

**Disruptive actions always wait for approval.** An action marked disruptive on the
Response actions page (block an IP, disable an account, isolate a host) cannot run
without an analyst saying yes, whatever the playbook says. Other actions wait too when
**Wait for an analyst to approve** is on. A webhook that only opens a ticket or starts a
workflow can run without approval.

Every run of an action is recorded in the response actions log, like a run by hand, with
the reason "Playbook *name*, for finding *title* (*id*)." It is run by the playbook
(`automatic`), and an approved one names the analyst who approved it (`approved_by`).

## Approvals

When a playbook reaches an action that waits for approval, it stops there and the step
shows on the **Approvals** page with the same sentence the Respond dialog shows, such as
what will be sent, to which server, with the target in bold. The navigation counts the
steps that wait, the finding says so at the top of its Overview, and the playbook's
approval channel, if it has one, gets a message with a link to the page.

- **Approve** runs the action, then the rest of the playbook, within a few seconds. The
  analyst who approved is recorded on the action run, in the audit log, on the finding
  and on the case.
- **Reject** stops the playbook for this finding. The steps after it do not run.
- Either can take a **note**, such as a ticket number. It is kept with the decision and
  shown on the finding.
- A step **nobody approves within 24 hours expires**. It is not done, and the playbook
  stops for that finding.

Only one decision counts. If two analysts press Approve at the same moment, one wins and
the other is told "It was already approved by ann." The action runs once. Viewers see
neither the page nor the buttons.

Everything a playbook does is written down twice: as a comment on the finding, by
"playbook *name*", and on the case's timeline once the playbook has opened or used a
case.

## A run, step by step

1. A detection raises a finding. Within 15 seconds the server that runs the background
   jobs sees it, and every playbook that is on and matches it starts.
2. The steps run in order. Each result is saved as it happens and listed under **Recent
   runs** on the Playbooks page.
3. A step that waits for approval pauses the run (**Waiting for approval**).
4. **A step that fails stops the run** (**Failed**). The steps after it do not run, and
   the finding says why. Nothing is retried, since an action that half-ran could do harm
   the second time; run it from the finding with **Respond** if it should still happen.
5. When every step is done, the run is **Done**.

Runs are kept for 90 days in the `<prefix>_playbook_runs` index.

Changing a playbook does not change the runs it already started. A run waiting for
approval keeps the steps it started with, so what an analyst approves is what was
planned. Deleting or turning off a playbook stops new runs; runs that already wait can
still be approved or rejected.

## Which server runs playbooks

Only one server runs playbooks: the server that holds the **background jobs** (see
[servers.md](servers.md)), in the job `playbooks`. It checks it still holds them before
each step. Approving and rejecting work on every server; the server running the jobs picks
the decision up within 15 seconds.

- Each run is **claimed** by creating a record whose ID is made from the finding and the
  playbook, so it is the same on every server. Only one server can create it, so a
  playbook runs at most once for a finding, even right after the jobs move to another
  server.
- If the jobs move between two steps, the next server goes on with the next step.
- If a server stops in the middle of a step, that step may or may not have happened, so the
  run is not started again. After about 15 minutes it is marked **Interrupted**: "The
  Signalith server stopped while this playbook ran, so its last step may or may not have
  happened." Check the finding and finish by hand.
- A finding is looked at for 30 minutes after it is raised. If no server runs the jobs for
  longer than that, playbooks do not start for the findings raised meanwhile.
- With `detections.scheduler: false` on every server, no playbook runs.

## Where the playbooks live

Playbooks are kept in `playbooks.yaml` in the lookups folder (setting `playbooks.file`,
environment `SIGNALITH_PLAYBOOKS_FILE`; a relative path is relative to the config file).
They hold no secrets: channels and actions are named, not copied, so their secrets stay
in their own files. Edit them on the page rather than by hand.

Like the notifications file, the playbooks file belongs to the server that runs the jobs.
On other servers the page shows the playbooks but cannot change them, and names the server
to use. If the jobs could move to a server whose playbooks file differs, the Servers page
says so; copy the file to every server that may run the jobs.

If the file cannot be read, no playbook starts, and the page shows the error.

## Example: block, then open a case

1. On **Response actions**, add the **Block IP on OPNsense/pfSense (alias API)** template
   and call it "Block IP on the edge firewall". It is disruptive.
2. On **Notifications**, add a Slack channel `#soc`.
3. On **Playbooks**, choose **Contain after approval** (or **Add playbook**):
   - **When**: only `auth-brute-force` and `auth-password-spray`, at high or above.
   - **Then**: Notify `#soc`; Run **Block IP on the edge firewall** on the **Source**;
     Open a case titled `Brute force from {src}` with the reuse box on; Set the finding
     to In progress.
   - **Ask for approval in**: `#soc`.

When brute force from 203.0.113.7 fires, Slack #soc gets the finding, then a message
that the playbook waits for approval to send the firewall request for 203.0.113.7, with a
link to the Approvals page. An analyst opens **Approvals**, adds "Confirmed in VPN logs"
and approves. The address is blocked, case C-12 "Brute force from 203.0.113.7" is opened with
the finding in it, and the finding is set to In progress. A second burst an hour later
waits for its own approval and goes into C-12 too.

## Shuffle and other SOAR tools

A playbook can hand off to a SOAR such as [Shuffle](https://shuffler.io). Add the SOAR's
webhook as a response action (the **Shuffle workflow webhook** template, see
[response-actions.md](response-actions.md#shuffle)), then add it to a playbook as a step.
Its target is any entity, so pick the one the workflow should get, or **A fixed value**.

The Shuffle template is marked disruptive, so the step waits for an analyst to approve it.
For a workflow that only enriches or opens a ticket, turn **Disruptive** off on that
action: the step then runs at once (unless **Wait for an analyst to approve** is on), the
SOAR gets the finding, and its workflow takes over. What the workflow does afterwards
shows in the SOAR, not in Signalith.

## API

| Route | Who | What it does |
| --- | --- | --- |
| `GET /api/playbooks` | admins | The playbooks, each with its `summary`, and the page's details: `revision`, `file`, `file_error`, `manage` (whether this server can change them) and `runs_on`, the `channels` and `actions` a step can use, and `approval_hours` |
| `PUT /api/playbooks` | admins | Replaces the playbooks with the body (`revision`, `playbooks`). A body with problems is refused with 400 and `problems` (`where`, `field`, `message`). A stale `revision`, or another server running the jobs, gives 409. |
| `GET /api/playbooks/runs?status=&finding_id=&playbook_id=&limit=` | analysts | Runs, newest first, with `total` and `waiting` (how many wait for approval). `status` takes one status or a comma list: `running`, `waiting_approval`, `approved`, `queued`, `succeeded`, `failed`, `rejected`, `expired`, `interrupted`. |
| `POST /api/playbooks/runs/{id}/approve` | analysts | Approves the step a run waits on. Body: `{"note": "..."}`, optional, up to 1,000 characters. Answers with the run. |
| `POST /api/playbooks/runs/{id}/reject` | analysts | Rejects it, with the same body. |

Approving or rejecting a run that no longer waits gives 409 with `"code": "decided"`, a
sentence saying why (already approved by someone, rejected, or expired) and the run as it
is now.
