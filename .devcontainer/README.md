# Disposable Wazuh lab (GitHub Codespaces)

A throwaway cloud machine with Docker for running the logtest suites. You create it, run the tests, and delete it.

## Lifecycle

```bash
# 1. Create (stops after 30 min idle, deleted 1 h after stopping)
gh codespace create -R SAMsploit1/shellcatch -b <branch> -m basicLinux32gb \
  --idle-timeout 30m --retention-period 1h --display-name wazuh-lab

# 2. Run the tests
gh codespace ssh -c <name> -- bash .devcontainer/lab.sh all

# 3. Delete
gh codespace delete -c <name> --force
```

Run `gh codespace list` to find `<name>` and `gh codespace list --json machineName` for machine types. You can also work interactively with `gh codespace code -c <name>` (VS Code) or `gh codespace ssh -c <name>`.

## Commands (`.devcontainer/lab.sh`)

| Command | What it does |
|---|---|
| `test [image]` | web-to-shell suite (`detections/web-to-shell/tests/run.sh`) in a throwaway manager |
| `selfmon [image]` | wazuh-selfmon suite in a throwaway manager |
| `all [image]` | both suites; exits non-zero if either fails |
| `manager` / `shell` / `stop` | long-running manager with both rule packs mounted, for manual `wazuh-logtest` |

The default image is `wazuh/wazuh-manager:4.14.8`. Override it with an argument or `WAZUH_IMAGE`, for example `lab.sh all wazuh/wazuh-manager:4.14.10`.

## What can't run here

- **auditd** (layer 1 on a real kernel): Codespaces gives no access to kernel auditing. The logtest cases still cover the rules.
- **The Wazuh 5.0 stack** (`detections/web-to-shell/wazuh5`): it needs the indexer and Content Manager API. Use the Azure lab.
- **FIM live checks**: possible with a manager plus agent, but not scripted here.

## Cost

Personal accounts get a free monthly Codespaces quota. Usage stops at the quota unless a spending limit is set. The short idle timeout and retention period above keep usage minimal. Check it on github.com → Settings → Billing.
