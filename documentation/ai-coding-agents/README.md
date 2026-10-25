# AI coding agent rules for Linux desktops

A starter set of Sigma rules that records what AI coding agents (Claude Code, Codex CLI, opencode, Gemini CLI, Cursor CLI, Goose, Crush, Amp, Aider) do on a Linux desktop. The target is an Arch and Hyprland setup such as Omarchy, but nothing in the rules is specific to Arch.

These rules give visibility and an audit trail. They do not stop anything. An agent that reads your SSH key will still have read it by the time the alert fires. Prevention needs sandboxing, scoped permissions and approval prompts, which sit outside Sigma.

All rules are `status: experimental` and have not been run against real desktop telemetry yet.

## How agents are identified

Coding agents run tool commands through a shell. The shell's command line holds the full command, and its parent is the agent:

| Agent | Shell started as | Parent seen in process events |
|---|---|---|
| Claude Code (native install) | `/bin/bash -c source ~/.claude/shell-snapshots/snapshot-bash-….sh … && eval '<command>'` | `~/.local/share/claude/versions/<version>` |
| Claude Code (npm) | same | `node …/@anthropic-ai/claude-code/…` |
| Codex CLI | `bash -lc <command>` | the `codex` binary, started with `codex-linux-sandbox` as argv[0] when sandboxed |
| opencode, Crush, Goose, Cursor CLI | `sh -c` or `bash -c` | the agent binary |
| Gemini CLI, Amp | `bash -c` | `node …/gemini` or `node …/@sourcegraph/amp/…` |
| Aider | `sh -c` | `python …/bin/aider` |

The Claude Code row was checked against a live process on 2026-10-25. The other rows come from the projects' source and documentation and should be checked on a real machine before the rules move past `experimental`.

The process_creation rules use the same four agent selections:

- `selection_agent_parent_image`: native agent binaries by file name
- `selection_agent_parent_path`: the Claude Code native install, whose binary is named after its version
- `selection_agent_parent_cli`: agents that run under node or python, by package path in the parent command line
- `selection_agent_snapshot`: the Claude Code shell snapshot path in the shell's own command line

Commands that the shell starts (for example `cat` inside a pipeline) have the shell as their parent and are not matched again. The match is on the shell's command line, which holds the whole command.

Agents also have built-in file tools (Read, Write, Edit) that do not start a shell. The auditd and file_event rules cover those.

## Rules

| File | Detects | Log source | Level |
|---|---|---|---|
| `proc_creation_lnx_ai_agent_credential_file_access.yml` | SSH keys, cloud credentials, token files, keyrings in an agent command | process_creation | medium |
| `proc_creation_lnx_ai_agent_browser_profile_access.yml` | Browser profile directories in an agent command | process_creation | high |
| `proc_creation_lnx_ai_agent_download_pipe_to_shell.yml` | `curl … \| sh` and `bash <(curl …)` | process_creation | medium |
| `proc_creation_lnx_ai_agent_reverse_shell_or_tunnel.yml` | `/dev/tcp`, `nc -e`, `socat exec:`, ngrok, cloudflared, `ssh -R` | process_creation | high |
| `proc_creation_lnx_ai_agent_persistence_location_write.yml` | Writes to shell rc files, Hyprland and UWSM config, systemd user units, autostart, authorized_keys; `systemctl --user enable`; crontab edits | process_creation | medium |
| `proc_creation_lnx_ai_agent_guardrail_tampering.yml` | Writes to an agent's own settings; agents launched with approvals or the sandbox off | process_creation | high |
| `proc_creation_lnx_ai_agent_secret_retrieval_cli.yml` | `gh auth token`, `secret-tool lookup`, `pass show`, `op://` references, cloud CLI token commands, `/proc/*/environ` | process_creation | medium |
| `proc_creation_lnx_ai_agent_privilege_elevation.yml` | `sudo`, `pkexec`, `doas`, `run0` in an agent command | process_creation | low |
| `lnx_auditd_ai_agent_sensitive_file_access.yml` | An agent process reading watched credential files | auditd | high |
| `lnx_auditd_ai_agent_persistence_file_write.yml` | An agent process writing watched startup files | auditd | medium |
| `file_event_lnx_ai_agent_persistence_file_creation.yml` | A native agent binary creating startup files | file_event | medium |
| `net_connection_lnx_ai_agent_uncommon_port.yml` | A native agent binary connecting to a port other than 80 or 443 | network_connection | low |

The low-level rules are for context. On their own they mostly show normal work.

## Log sources

**Process, file and network events.** The rules use the Sysmon field names (`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `TargetFilename`, `DestinationPort`), which is what Sysmon for Linux produces (https://github.com/microsoft/SysmonForLinux). Enable ProcessCreate (event 1), NetworkConnect (event 3) and FileCreate (event 11). Sysmon for Linux is not in the Arch repositories; check the AUR or build it from source. Any other collector works if a pySigma pipeline maps its fields to these names.

**auditd.** Install `audit`, enable `auditd.service`, and load `ai-agents.rules` from this directory after replacing `/home/USER`. The two auditd rules match on the audit key and the process executable in SYSCALL records, so they do not need PATH records to be joined.

## Known gaps

- Sigma matches one event at a time. A command run by a script that the agent wrote and then ran is one process further down the tree and is not matched by the process_creation rules. A backend with process ancestry (or a correlation rule on process GUIDs) would close this.
- Agents installed from npm run as `node`. The file_event and network_connection rules cannot tell them apart from other node programs, because those events carry no command line. The auditd rules include `node` and `bun` on purpose and accept the extra noise.
- Single `>` redirects into rc files are not matched by the persistence rule (only `>>`), because the Claude Code shell wrapper itself contains redirects. The auditd and file_event rules still see the write.
- An agent can hide a command from command-line matching by writing it to a file first, or by encoding it. These rules catch careless or injected behaviour, not a determined adversary.
- Agents running inside a container or a VM appear as the container runtime, not as the agent.

## Tracking these rules in detection-ledger

The ledger records the history of published detection rules: every version, what changed, and how it was classified. Two ways to use it for this pack:

1. **After upstream acceptance.** If the rules are contributed to SigmaHQ and merged, the ledger picks them up as part of its `sigma` source with no extra work. Changes to them (new agents, new paths, false-positive filters) then show up in `changes_since` and in watches like any other Sigma rule.
2. **Before that, as a custom source.** The ledger can capture an organisation's own repository through `custom_sources` in `config.yaml` (see `docs/custom-sources.md` in detection-ledger), for example with `adapter: sigma`, this repository's URL and `rule_paths` limited to the `*ai_agent*` files with `:(glob)` patterns. That gives a versioned record of how the pack changes while it is tuned.

Field results go in as observations, which never overwrite the rule history: for example kind `false_positive_report` with the rule ID and the command that caused it, or a kind for confirmed hits. On the local server this needs `DETECTION_LEDGER_ENABLE_WRITES=true`; on the hosted endpoint it goes through the opt-in feedback route.

Over time that gives a public, dated record of what watching an AI agent on Linux catches and what it gets wrong.
