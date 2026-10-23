# Detecting Malicious BPF Programs

Detecting eBPF abuse means answering three questions: what BPF objects exist on this host, who loaded them, and does the system's behaviour match what those objects claim to do. This chapter builds a layered detection approach, from `bpftool` inventories to loader monitoring, kernel logs and memory forensics, with the assumption that a capable attacker may be lying to at least one layer.

## Layer 1: inventory with bpftool

`bpftool` talks to the kernel through the `bpf()` syscall and lists programs, maps, links, BTF objects and attachments.

```bash
sudo bpftool prog show -j    > progs.json   # id, type, name, tag, loaded_at, uid, map_ids
sudo bpftool map show -j     > maps.json
sudo bpftool link show -j    > links.json
sudo bpftool net show                         # XDP and tc attachments per interface
sudo bpftool cgroup tree                      # cgroup-attached programs
sudo bpftool perf show                        # kprobe/uprobe/tracepoint attachments with pids
```

Fields worth baselining: program `type`, `name`, `tag` (a hash of the instructions), `loaded_at`, `uid`, `pids` (which processes hold references, on kernels and bpftool builds that support it) and attached hooks. The Wazuh project publishes an approach that compares each loaded program's tag with an approved list and alerts on unknown tags. Tags change when programs are rebuilt, so allowlists need maintenance alongside agent upgrades.

For any unexpected program:

```bash
sudo bpftool prog dump xlated id <ID>   # translated bytecode with helper names
sudo bpftool prog dump jited id <ID>    # native code
```

Look for calls to `bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal`, and packet-modifying helpers in programs that are supposed to be read-only tracers.

## Layer 2: cross-checking enumeration paths

Fournier, Afchain and Baubeau showed that an implant can hide its programs and maps by hooking the `bpf()` commands that enumerate IDs (`BPF_PROG_GET_NEXT_ID`, `BPF_MAP_GET_NEXT_ID`) and the reads that return results. Datadog Security Labs later noted that a program hidden from ID enumeration can still be exposed by requesting specific IDs directly (`bpftool prog show id N` uses `BPF_PROG_GET_FD_BY_ID`), because the hook may not cover that path. A simple check is to walk IDs from 1 to the highest seen plus a margin and compare with the enumerated list. Gaps are normal (unloaded programs); IDs that resolve but were not enumerated are not.

Other independent views:

- `/proc/<pid>/fdinfo/<fd>` for processes holding BPF file descriptors shows `prog_type`, `prog_tag` and `prog_id`.
- `/sys/fs/bpf` lists pinned objects.
- `/sys/kernel/debug/tracing/kprobe_events` and `uprobe_events` show dynamic probes created through tracefs.
- The `bpf_stats_enabled` sysctl, when enabled, adds run time and run count to `bpftool prog show`, revealing programs that run far more than expected.

## Layer 3: monitoring loads

Hogan's DEF CON 29 talk recommended monitoring every `bpf` syscall, on the principle that only trusted programs should use eBPF, and noted that eBPF can monitor itself and even extract program bytecode at load time. In practice:

- Audit the `bpf` syscall with auditd: `-a always,exit -F arch=b64 -S bpf -k bpf_load`.
- Use your eBPF security agent to alert on `BPF_PROG_LOAD` from processes outside an allowlist (agent binaries, systemd, container runtimes, approved observability tools). Falco's default rules and Tetragon policies can express this.
- Alert on `bpftool` invocations that detach programs or delete maps. Elastic ships a prebuilt rule for "BPF Program Tampering via bpftool".
- Watch for new files in `/sys/fs/bpf` and new systemd units that run loaders.

On kernels with BPF LSM, policies can go further and deny `bpf()` program loads outside approved contexts (Chapter 6).

## Layer 4: kernel log and side effects

- `dmesg` and the journal record the warning when a program using `bpf_probe_write_user` is loaded. Fournier et al. point out that an implant may also hook the syslog path to hide it, so ship kernel logs off-host in real time.
- Behavioural inconsistencies are strong signals: a file whose content differs when read by different processes; `kill` returning `ESRCH` for a PID that exists in `/proc` listings from another view; network traffic visible on an upstream tap or flow logs but absent from host packet capture.
- Fournier et al.'s summary advice: look for the actions a rootkit must block or lie about; if you can, load a kernel module or eBPF program to list eBPF programs from inside the kernel; and monitor network anomalies at infrastructure level.

## Layer 5: memory forensics

Memory acquisition with tools such as LiME or AVML, followed by analysis in Volatility 3, provides a view the running implant cannot filter. Hogan's 2021 talk mentioned that Volatility planned eBPF plugins; check the current Volatility 3 plugin list for your version rather than assuming specific plugin names. Even without dedicated plugins, kernel structures for BPF programs and maps can be located from symbols, and comparing them with the live `bpftool` output reveals hidden objects.

## Detection matrix

| Signal | Source | Strength |
|---|---|---|
| Unknown program tag | bpftool inventory | Good, if baseline maintained |
| ID resolves but not enumerated | ID walk | Strong indicator of hiding |
| `bpf()` load from unexpected binary | auditd / agent | Strong; needs allowlist |
| `bpf_probe_write_user` warning | Kernel log shipped off-host | Strong for that helper |
| Host vs network capture mismatch | Tap / flow logs | Strong for XDP/tc implants |
| Hidden objects in memory image | Volatility | Strongest, costly |

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

Build and test a BPF inventory check in a lab VM.

1. Enable statistics: `sudo sysctl kernel.bpf_stats_enabled=1`.
2. Capture a baseline JSON with the commands above and store it with a hash.
3. Add the auditd rule, reload with `sudo augenrules --load`, then run `sudo bpftrace -e 'kprobe:do_sys_openat2 { @[comm] = count(); }'` for ten seconds.
4. Run `sudo ausearch -k bpf_load` and confirm the load was recorded with the `bpftrace` executable path.
5. Write a script that diffs current `bpftool prog show -j` against the baseline by tag and type and walks program IDs to the maximum plus 50. Run it while bpftrace is active and after it exits.

## Common pitfalls

- Trusting a single enumeration path.
- Keeping kernel logs only on the host.
- Building tag allowlists once and never updating them after agent upgrades.
- Forgetting cgroup, tc and XDP attachments that do not appear in tracing views.
- Collecting memory images without recording kernel version and symbols needed for analysis.

## Exercises

1. Write an auditd plus SIEM rule that alerts on `bpf()` loads outside an allowlist of binaries and test it against bpftrace and a container runtime.
2. Extend the inventory script to report programs with packet-modifying or user-memory-writing helpers in their translated bytecode.
3. Acquire a memory image of a lab VM with AVML and locate BPF program structures with Volatility 3.

## Further reading

- bpftool documentation: `man bpftool-prog`, `man bpftool-map`; kernel sysctl docs: <https://docs.kernel.org/admin-guide/sysctl/kernel.html>
- G. Fournier, S. Afchain, S. Baubeau, "eBPF, I thought we were friends!", DEF CON 29 (2021)
- P. Hogan, "Warping Reality", DEF CON 29 (2021)
- Elastic rule "BPF Program Tampering via bpftool": <https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/defense_evasion_bpf_program_tampering>
- Wazuh, "Detecting eBPF-based attacks on Linux endpoints": <https://wazuh.com/blog/>
- Related books: **ai-driven-threat-hunting**, **web3-incident-response**
