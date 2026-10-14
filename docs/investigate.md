# Investigate with AI

**Investigate with AI** gives an analyst a first pass at a finding. One click on a finding
gathers the evidence, lets an AI model run a few more searches of its own, and returns a
short verdict with a timeline and the facts behind it. The analyst decides what happens
next.

It is **off until an admin turns it on**, because unlike **Ask**, which only sends the
question, it sends event data to the model.

## What it does

When an analyst clicks **Investigate with AI** on a finding, Signalith:

1. Gathers the evidence:
    - the events behind the finding (the detection's own search over its window);
    - where each of the finding's users, hosts and addresses shows up, from 7 days before
      the finding to 1 day after it (by data model and source type);
    - threat intel matches for the finding's values;
    - other findings about the same users, hosts and addresses;
    - asset and identity context (priority, business unit, watchlist) and analyst notes.
2. Shows exactly what will be sent, with masked values already replaced, and asks the
   analyst to send it. Nothing leaves Signalith before that click.
3. Sends it to the model, which may ask for up to 3 more searches at a time, in up to 3
   turns, 8 in all. Each search is shown as it runs, with a button to open it in Search.
4. Returns:
    - a **verdict**: likely real, likely benign or unsure, with how confident the model is;
    - a short **summary** and a **timeline** of what happened;
    - the **evidence** the verdict rests on, each point linked to the searches it came from;
    - **suggested response actions**, only from the ones set up on the Response actions page.
      Nothing runs by itself: **Review** opens the usual Respond dialog with the action and
      target filled in, where the analyst checks it, gives a reason and confirms;
    - **next steps** for a person to check.
5. **Save to case** adds the write-up to the finding's case as a note, or to a case you pick
   (the finding is added to it too).

It changes nothing. The query language has no command that writes, every search is limited
to 31 days and its first 10 rows are sent, and response actions need a person.

## Turning it on

An admin opens **Settings → AI assistant**:

1. Set up a model (**Provider**, **Model**, **API key**), the same one **Ask** uses.
2. Turn on **Investigate with AI**. The page asks to confirm, since event data will be sent.
3. Optionally list **Fields never sent** (see below).

Or in `signalith.yaml`:

```yaml
assistant:
  provider: openai
  url: http://localhost:11434/v1
  model: qwen3:14b
  investigate: true
  mask_fields: [user, src_user, _raw]
```

Only analysts and admins can investigate. Viewers do not see the button.

## Keeping data private

- **Use a model on your own hardware.** With Ollama, LM Studio or vLLM on your network,
  event data never leaves it. The dialog says whether the model is on your network or
  outside it. Ollama's default context window is small; start it with
  `OLLAMA_CONTEXT_LENGTH=32768` (or more) so the whole investigation fits.
- **Mask fields.** Values of the fields in **Fields never sent** are replaced with stand-ins
  such as `masked-user-1` wherever they appear, including inside the event text and other
  fields. The same value always gets the same stand-in, so the model can still tell
  accounts apart and search for them: Signalith puts the real value back into its queries
  before they run, and into its write-up before you read it. Wildcards work (`*_user`).
- **Leave out the event text.** Add `_raw` to **Fields never sent**.
- **Always masked:** fields whose names contain password, passwd, secret, token, api_key,
  apikey, cookie, authorization, session_id or private_key.

Every investigation is written to the audit log (`finding investigated with AI`, with `by`,
`finding`, `model`, `sent_to`, `chars_sent`, `ai_searches` and `verdict`), and a failed one
as `Investigate with AI failed`.

## Good to know

- An investigation takes from a few seconds to a few minutes, depending on the model. Up to
  3 run at once on each server.
- The model can be wrong. Treat the verdict as a lead: the evidence lists the searches it
  came from, so you can check each one.
- The write-up stays in your browser until you save it to a case. Opening the finding again
  in the same tab shows the last one.

## API

| Route | Role | What it does |
|---|---|---|
| `GET /api/investigate` | analyst | Whether it is on, the model, where data is sent, whether that is on your network, and the masked fields |
| `POST /api/findings/{id}/investigate/preview` | analyst | Gathers the evidence and returns the first message exactly as it would be sent, without sending it |
| `POST /api/findings/{id}/investigate` | analyst | Runs the investigation, streaming one JSON object per line: `status` and `step` events, then a `result` or an `error` |

Both `POST` routes answer `409` with `code` `no_model` or `off` when an admin has not set it up.
