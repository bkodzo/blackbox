# Dashboard

`blackbox dashboard` serves a read-only web view of a log for the people who
review what agents do: auditors, managers, and security officers. It shows
what happened in plain language, flags that need attention, and whether the
log can be trusted, without the command line.

```
blackbox dashboard --log blackbox.jsonl --checkpoints blackbox.checkpoints.jsonl --pub key.pub
```

Then open http://127.0.0.1:8090. A [live demo](https://bkodzo.github.io/blackbox/)
shows it on a scripted sample log.

The dashboard needs only the log, its checkpoints, and the public key, never
the signing key. It can run on the gateway host, or on an auditor's own
machine against a copy of the files. It runs separately from the gateway, so
it cannot slow down or stop agent traffic.

## Pages

| Page | Shows |
|---|---|
| **Overview** | Calls, sessions, and flagged calls in total and in the last 24 hours; calls, flags, and tokens per day for 30 days; the tools used most; the latest flagged calls and calls |
| **Sessions** | Every session, most recent first, searchable by session, agent, or principal, and filterable to sessions with flags |
| **Session** | What happened in one session, call by call: the tools the model asked to use, their risk, and every flag with its explanation |
| **Flags** | Every flagged call, filterable by kind, agent, and date, with what each kind means |
| **Entry** | One entry in full: who sent it, what was asked and answered, tool calls and results, reasoning, both bodies, and its hash and signature. The entry can be downloaded exactly as stored |
| **Integrity** | Whether the log is intact, with warnings, or tampered with, the checkpoints, and a button to check again |
| **Report** | A printable summary of one session or a date range: the integrity result, totals, flags by kind, every flagged call, and the session's timeline. Print it to save a PDF |

A strip at the top of every page shows the latest integrity result and how
many entries were added since it ran.

## How it reads the log

At startup the dashboard reads the log once and keeps a small summary of each
entry in memory: where it is in the file, its type, time, session, agent,
tools, and flags. Bodies stay on disk and are read only when an entry is
opened, so memory grows with the number of entries, not their size.

It then follows the log as the gateway appends to it, checking for new
entries every second. Open pages say when new entries arrive. A final line
still being written is skipped until it is complete. If the log becomes
shorter than what was read, entries were removed from its end; every page
says so in red until those entries are back, as they are once a copy being
rewritten in place is complete. If the file is replaced, or an entry already
read changes, the log is read again from the start and every page says so.

Lists read the log without checking it. Whether the log can be trusted is
decided on the Integrity page by the same code as `blackbox verify`, so the
two always agree. The check runs when the dashboard starts and whenever
someone presses "Check again now".

Lists show at most 500 rows; a longer session shows its 500 most recent calls
with a link to earlier ones. The entry page shows the first 256 KiB of each
body; the downloaded entry has everything.

## Static export

```
blackbox dashboard --export site --export-note "Snapshot for the March review."
```

writes every page to the `site` directory as static files, checks the log
first, and exits. The pages link to each other by file name, so the directory
can be opened from disk, attached to a ticket, or served by any web server.
Every entry gets its own page, so exports suit small logs. The snapshot shows
the integrity result as of when it was made; searching, filtering, and checking
again need the live dashboard.

The [live demo](https://bkodzo.github.io/blackbox/) is such an export, made by
the `demo` workflow from a sample written by
[examples/demolog](../examples/demolog/main.go). That program runs scripted
agent traffic through blackbox's own recorder, so its flags are the gateway's
real findings.

## Security

- **Read-only.** The dashboard opens the log and the checkpoints only for
  reading. It has no way to change them.
- **Local by default.** It listens on 127.0.0.1. It answers only requests
  addressed to `localhost`, a loopback address, or a name passed with
  `--allow-host`, so a web page on another site cannot reach it by pointing
  its own domain at this machine.
- **No login.** Anyone who can reach the dashboard can read every prompt and
  response in the log. To share it, put it behind access control you already
  trust, such as a reverse proxy with single sign-on, and pass the name people
  will use with `--allow-host`.
- **Recorded text is shown as text.** Prompts, replies, and tool arguments
  come from agents and models and may contain HTML. Every page escapes them,
  the strict content security policy blocks scripts and styles from anywhere
  but the dashboard itself, and downloaded entries are never rendered.
- **One action.** "Check again now" is the only request that does anything,
  and it is accepted only from the dashboard's own pages. While a check runs,
  further requests wait for it instead of starting another.

## Settings

| Flag | Default | Meaning |
|---|---|---|
| `--log` | `blackbox.jsonl` | Audit log |
| `--checkpoints` | `blackbox.checkpoints.jsonl` | Checkpoint file (required) |
| `--no-checkpoints` | off | Check without a checkpoint file; removals from the end cannot be detected |
| `--pub` | `~/.blackbox/key.pub` | Gateway public key |
| `--listen` | `127.0.0.1:8090` | Address to serve on |
| `--allow-host` | none | Host name or address the dashboard may be reached under, besides localhost; repeat or separate with commas |
| `--export` | none | Write every page to this directory as static files, then exit |
| `--export-note` | none | Text shown at the top of every exported page |
