# Ansible role `cfab_fabric`

Installs the `cfab` package from its apt repository on a host and drives a gated rollout, one
operation per run, selected by tag. It carries nothing about any particular site: the declaration
(`fabric.toml`) is the operator's and comes in through `cfab_declaration`.

## Use from your own repository

`roles/requirements.yml`:

```yaml
- src: https://github.com/shkolnik/cfab.git
  scm: git
  version: v0.4.9            # role tag = package version, for now
  name: cfab_fabric
  # the role lives under ansible/roles/cfab_fabric in the repo
```

Galaxy cannot fetch a role from a subdirectory, so either vendor it
(`git subtree`/`git archive`) or check the repo out and point `roles_path` at `ansible/roles`.

Playbook:

```yaml
- hosts: pve
  become: true
  vars:
    cfab_declaration: "{{ playbook_dir }}/files/cfab/fabric.toml"
  roles:
    - cfab_fabric
```

Run, always `-l` one host at a time:

```
ansible-playbook cfab.yml -l pve2 --tags probe      # read-only inventory of the host; paste it back
ansible-playbook cfab.yml -l pve2                   # install: apt repo, package, declaration, unit (DISABLED). No network change.
ansible-playbook cfab.yml -l pve2 --tags apply      # arm a 10-min revert, enable+start, verify, print
ansible-playbook cfab.yml -l pve2 --tags disarm     # keep it: stop the revert timer
ansible-playbook cfab.yml -l pve2 --tags rollback   # undo now: disable + cfab down (package stays)
```

Inventory names **are** the `[[member]]` names (`cfab_host` defaults to `inventory_hostname` and
is written into the unit's environment). Requires ansible-core >= 2.15 on the control node
(`deb822_repository`) and `python3-debian` on the host (the role installs it).

## Variables

| variable | default | meaning |
|---|---|---|
| `cfab_declaration` | **required** | path on the control node of this host's `fabric.toml` |
| `cfab_nics` | the `nic = "…"` names in the declaration | wires the probe inspects |
| `cfab_version` | `""` = newest in the repository | pin, e.g. `0.4.9-1`; equal version = apt no-op |
| `cfab_apt_uri` / `cfab_apt_suite` / `cfab_apt_component` | `https://pkg.jshkol.com` `stable` `main` | where the package comes from |
| `cfab_conf_path` | `/etc/cfab/fabric.toml` | where the declaration lands |
| `cfab_host` | `inventory_hostname` | the `[[member]]` row this host runs as |
| `cfab_revert_minutes` | `10` | apply arms a timed revert; `--tags disarm` within this window keeps the fabric |
| `cfab_status_wait` | `90` | seconds `cfab status --wait` waits for UP after bringup |

## What install puts on the host

| what | where |
|---|---|
| signing key, armored (pinned in the role: trusting a key is a decision that belongs in git history) | `/usr/share/keyrings/jshkol-archive-keyring.asc` |
| signing key, dearmored, what `Signed-By` points at | `/usr/share/keyrings/jshkol-archive-keyring.gpg` |
| deb822 sources entry | `/etc/apt/sources.list.d/jshkol.sources` |
| `cfab` package (pulls `nftables iproute2 ethtool libpcre2-8-0`) | `/usr/bin/cfab` |
| the declaration | `/etc/cfab/fabric.toml` |
| `cfab-revert`, generated: what the timer and `--tags rollback` run | `/usr/local/sbin/cfab-revert` |
| `cfab.service` with `cfab_host`/`cfab_conf_path` baked in, **installed disabled** | `/etc/systemd/system/cfab.service` |

Install never changes the network. `apt` will not replace a package at an equal version string,
even if the bytes differ: bump the version or `dpkg -i` to move a host onto another build.

## Apply, and the first member of a fabric

Apply = `systemd-run --on-active=<revert_minutes>m cfab-revert`, `systemctl enable`,
`reload-or-restart` (start, or SIGHUP re-apply in place if active), `cfab status --wait`, print.
`cfab status` exits 0 = `UP`, 1 = `UP-DEGRADED`, 2 = `FAILED`, 3 = `DOWN`; the apply task is strict
and fails on anything but 0, with the revert timer still armed, except for one shape:

The first member has no peer, so it honestly reads `FAILED (0/2 | 0/18 | 0/6)`, and every member
before the last reads `UP-DEGRADED`. The task accepts a non-UP status only when **every** reason
line is a peer-absence line (`down <zone>:<segment>:.<node>` or `down <zone>:fallback:.<node>`),
no reason line names a local problem, and every node named down is down on all its links. A node
up on one wire and down on another is a local fault and fails the play. Accepting a peers-absent
status says only that nothing is wrong *here*; `--tags disarm` remains a separate, deliberate step.

## What the role does not do

- Edit `/etc/network/interfaces`. Bringup adds tagged sub-interfaces on the wires and never
  assigns or flushes an untagged address on them (the admin session rides one); it refuses when
  no wire carries an untagged IPv4 address at all.
- Resolve a running `frr`: cfab's embedded engine and frr coexist only if their BFD ports differ
  (`[bfd] port` in the declaration). The probe prints frr's state.
- Act on `bridge-nf-call-iptables`, corosync rings, or Proxmox storage config. The probe prints
  them; a host where bridged frames traverse the forward chain is a site decision.

Removing the install:

```sh
ansible-playbook cfab.yml -l pve2 --tags rollback   # first, if the fabric is up
apt-get purge cfab
rm -f /etc/systemd/system/cfab.service /usr/local/sbin/cfab-revert && systemctl daemon-reload
rm -rf /etc/cfab
rm -f /etc/apt/sources.list.d/jshkol.sources /usr/share/keyrings/jshkol-archive-keyring.{asc,gpg}
```
