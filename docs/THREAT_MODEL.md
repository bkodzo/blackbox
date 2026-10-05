# Threat model

This document states what blackbox protects against, what it does not, and
what it assumes.

## What blackbox claims

If `blackbox verify` reports a log as intact against a public key, and the
checkpoints it was given include copies kept somewhere the attacker could not
change, then:

1. Every entry in the log was written by a gateway holding the matching
   private key.
2. No entry has been changed since it was written, and every entry has exactly
   one valid encoding, so every JSON parser reads the content that was verified.
3. No entry has been removed, inserted, or reordered.
4. No entry up to the latest checkpoint has been removed from the end, and the
   log was not truncated and rewritten after any of those checkpoints.

It also flags, but does not prevent, suspicious agent behaviour (see below).

## Assets

- **The log**: the record of what agents asked and what models returned.
- **The signing key**: whoever holds it can write entries that verify.
- **Checkpoints**: signed statements of which entry a log had at a sequence
  number and time.

## Attackers and what happens

| Attacker | Can do | Detected by |
|---|---|---|
| Edits an entry | Change any bytes | Hash mismatch on that entry |
| Re-encodes an entry (duplicate or renamed keys, whitespace) so other tools read it differently | Present different content to other parsers | Entry is not in canonical form |
| Deletes or inserts an entry | Remove or add lines | Sequence gap or broken back-link |
| Reorders entries | Swap lines | Sequence or back-link mismatch |
| Edits an entry and recomputes the whole chain | Produce a consistent chain | Signatures fail without the private key |
| Deletes entries from the end | Leave a valid signed prefix | Log shorter than a checkpoint |
| Truncates the log, deletes local checkpoints, and lets the gateway write new entries up to the old length | Produce a valid log of the right length | Shipped checkpoint disagrees with the new entry at that sequence number |
| Restarts the gateway on a truncated log | Extend the chain over the gap | The gateway refuses to start below its own checkpoint |
| Edits a checkpoint's sequence number or time | Make an intact log look tampered, or hide truncation | Checkpoint signature fails |
| Copies a checkpoint from another log signed by the same key | Vouch for the wrong log | Checkpoint names a different log |
| Removes the final newline so the last entry looks like a crash | Have the gateway discard it | The gateway keeps a complete signed entry and records the repair |
| Replaces the log with one signed by another key | Present a different log | `verify` checks against the auditor's copy of the public key |

## Agent behaviour that is flagged

blackbox sees the full conversation on every call, so it can notice when an
agent, or something that has taken control of it, misrepresents what happened:

- tool results for calls the model never made (`orphan_tool_result`), as in a
  prompt injection that fakes an approval, or for calls already answered
  (`duplicate_tool_result`);
- tool results that cannot be checked because no earlier turn was seen
  (`unverifiable_tool_result`);
- earlier messages, the model's tool calls (including their arguments), or the
  model's reply text changed or left out between turns, replies attributed to
  the model that it never sent, or messages placed ahead of its reply
  (`history_rewritten`), or older turns dropped (`history_truncated`);
- calls the model only wrote as text that the agent then ran
  (`text_tool_call_executed`);
- tools or the system prompt changed mid-conversation;
- a different model answering than the one requested;
- high-risk tools requested, including tool calls the model wrote as text.

Conversations are tracked with or without a session header, and the state is
rebuilt from the log after a restart. These are flags for review, not blocks.
They are heuristics about how agents and servers lay out messages: an unusual
layout can be missed or flagged. The tamper-evident log is the guarantee; the
anomaly checks guide review.

## Assumptions

- **The private key is protected.** It is created with owner-only permissions.
  An attacker who has the key can write a log that verifies. Keep it on the
  gateway host only, outside the log's directory, and rotate it if the host may
  be compromised. A new key starts a new log file; the gateway will not
  continue a log signed by another key.
- **The auditor's public key is genuine.** Verification against an attacker's
  public key proves nothing. Distribute the public key separately from the log.
- **Checkpoints leave the gateway host.** If the attacker controls every copy of
  the checkpoints, they can truncate the log and the checkpoint file together.
  Ship checkpoints from stdout to a log collector or another machine.
- **Entries newer than the last checkpoint are not yet protected against
  removal.** Someone who controls the gateway host can kill it and cut entries
  written since the last checkpoint; on restart this looks like a crash (an
  unclean shutdown warning). Checkpoints are written at least every 100 entries
  or 30 seconds by default; lower `--checkpoint-records` or
  `--checkpoint-interval` to narrow the window.
- **Agents go through the gateway.** blackbox records only traffic sent to it.
  Network policy should make the gateway the only route to the model server.
- **Access to the gateway is controlled.** The gateway has no authentication of
  its own; anyone who can reach it can use the model server through it.

## Not covered

- **A compromised gateway host.** An attacker with root on the gateway can read
  the key and write false entries going forward. blackbox protects records
  already written and checkpointed elsewhere, not the future output of a
  compromised machine.
- **Agent identity.** Agent, session, and principal names come from request
  headers and are recorded as `self_declared`. A misbehaving agent can claim
  any name. Gateway-issued agent credentials are planned.
- **What tools actually did.** blackbox sees what the model asked for and what
  the agent reported back, not the tool execution itself. Auditing tool
  servers directly is planned.
- **Conversations that begin before the gateway sees them.** Tool results in
  the first observed turn are flagged as unverifiable, not checked.
- **Concurrent calls in one session.** If several agents share a session ID and
  call at the same time, history checks can raise false alarms. Sub-agents
  should use their own session ID with `X-Blackbox-Parent-Session`, or send no
  session ID and let conversations be tracked by content.
- **Protocol upgrades.** Refused by default. With `--allow-upgrades`, traffic
  after a switch to another protocol (a WebSocket, for example) is passed
  through but not recorded; only the request that asked for it is.
- **Crash window.** The agent receives its response before the record is
  durable. A hard crash can lose calls still queued in the recorder and the
  current 50 ms write batch. The loss is flagged at the next start. `--sync
  always` removes the batch window but not the queue.
- **Fail-open mode.** With `--fail-open`, traffic continues after the log fails
  and is not recorded. In the default mode, a call already being answered when
  the log fails can finish its response unrecorded; no new call is forwarded.
- **Few-shot examples, and conversations without a session ID.** A
  conversation the gateway has never seen may open with model replies written
  by the agent (examples, or fabricated history). These are not flagged, since
  they cannot be told apart from a conversation that began before the gateway.
  Without a session ID, a conversation is recognised only by its opening
  messages, so fabricated history under an opening the gateway has not seen is
  not detected. Send `X-Blackbox-Session` for the strongest checks.
- **Denial of service.** Anyone who can reach the gateway can use its capacity.
  Per-client limits stop one address from taking every slot, but many
  addresses can still exhaust it. Requests refused for capacity are counted,
  not recorded.
- **Upgraded connections.** With `--allow-upgrades`, a connection that switched
  protocols is not subject to the response idle limit or the shutdown grace
  period.
- **Confidentiality.** The log contains full prompts, responses, and any model
  reasoning in plain text. It is created with owner-only permissions but is not
  encrypted, and there is no redaction yet.
- **Hidden reasoning.** Reasoning a server does not return, or returns only in
  encrypted form, cannot be recorded or reviewed.
- **Detection heuristics.** Tool calls written as text are found by pattern and
  can be missed (non-JSON formats, calls with no arguments, or calls to tools
  that were not offered and are not in the risk map, which are only counted) or
  over-reported. A scan cut short by its limits is flagged.
- **Agents that never echo.** An agent that drops the model's reply from its
  history entirely is flagged on every turn; this is deliberate.
