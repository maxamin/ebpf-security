# Offensive Abuse of eBPF in Public Research

Security researchers have published several detailed studies of how eBPF can be turned against the host it runs on. This chapter summarises those public findings by capability, so that defenders know what to look for. It deliberately stays at the level of mechanisms and observable side effects. It contains no rootkit code and no step-by-step build instructions.

## Why attackers are interested

Hogan's DEF CON 29 talk "Warping Reality" framed the motivation. Traditional kernel rootkits, built as loadable modules that hook the syscall table, give attackers complete visibility and control but are fragile: a small bug crashes the machine, every kernel update risks breakage, and some environments (Hogan cites managed Kubernetes such as Amazon EKS) block arbitrary modules. eBPF offers much of the same visibility with the verifier's guarantee that the program will not crash the kernel, plus portability across kernel versions through CO-RE. Fournier, Afchain and Baubeau's DEF CON 29 talk listed similar attractions: cannot crash the host, minimal performance impact, and a growing number of vendors already using eBPF, so its presence is not suspicious. Their stated purpose was that eBPF's "safety" should not blind security administrators.

## Capabilities documented in public talks

| Capability | Mechanism described publicly | Limits noted by researchers |
|---|---|---|
| Hide files and processes | Rewrite results returned to user space, for example directory listings, using `bpf_probe_write_user` on syscall exit | Cannot change kernel memory; kernel-side tools and audit still see the truth |
| Block or fake syscalls | `bpf_override_return` on syscalls such as `kill` to return `ESRCH`, making a process appear absent | Requires override support; syscall may still execute in other cases |
| Hide BPF objects | Intercept `bpf()` ID enumeration commands to skip the attacker's programs and maps | Other enumeration paths may disagree |
| Persistence | Tamper with reads of `authorized_keys`, `passwd`, crontab so `sshd` or `cron` see attacker content while the file on disk is unchanged | Loader must be restarted after reboot |
| Network C2 and exfiltration | XDP/tc programs read and drop command packets before firewalls and packet capture, rewrite or clone traffic | Infrastructure-level monitoring still sees packets on the wire |
| TLS interception | uprobes on OpenSSL functions read or alter plaintext | Specific to library versions and paths |
| Anti-forensics | Block signals or module loading; send SIGKILL to tools | Noisy if analysts expect those actions to work |

Fournier and colleagues released their proof-of-concept as `ebpfkit` alongside a monitor, `ebpfkit-monitor`, for detection research. Dileo's DEF CON 27 talk explored similar ground earlier, including covert inter-process communication through maps and reliable user-memory corruption from tracing programs. Hogan released `bad-bpf` as an educational collection. These repositories exist for research; this book does not reproduce them, and you should only study them in isolated lab VMs.

## Limits the researchers themselves highlighted

Public work is clear about what eBPF malware cannot easily do, and these limits are where detection lives:

- **No kernel memory writes.** Hogan notes eBPF programs cannot alter kernel memory directly, so kernel-side security products such as auditd are unaffected; the tampering targets user-mode controllers, log readers and network traffic.
- **Warnings.** Loading a program that uses `bpf_probe_write_user` triggers a kernel log warning that it "may corrupt user memory" (Fournier et al.).
- **Races.** If a user-space process reads quickly, or on another thread, tampering may fail, which a careful tool can detect.
- **No reboot persistence on its own.** Programs must be reloaded, so a loader on disk or in an image is required.
- **A resident process or pinned objects.** Programs attach through a process or pinned links; something must stay in memory or in bpffs.

Fournier et al. concluded that a perfect eBPF rootkit is technically possible "with enough time, motivation, insanity" but that defenders should look for the actions a rootkit must block or lie about to protect itself.

## Classic BPF in the wild

Not all observed malware uses extended BPF. Reports on BPFDoor, attributed by PwC to a group it names Red Menshen, describe classic BPF socket filters on raw sockets that wake a backdoor when a packet with attacker-defined bytes arrives, without listening on any port. Intezer's analysis of Symbiote, as summarised by Risky Business, describes BPF used to hide the malware's traffic from packet captures on the infected host. Raw packet sockets and their owning processes are listed by `ss -0 -p` and `/proc/net/packet`, and `ss` can print attached classic BPF filters with `--bpf` when run as root, which gives defenders a hunting angle.

## Verifier exploitation is different

A rootkit uses eBPF as designed, with privileges. Verifier exploitation abuses bugs to gain privileges or kernel read/write. They lead to different defences: the first is about controlling who may load programs and monitoring what is loaded; the second is about patching, disabling unprivileged BPF and reducing attack surface. See Chapter 6 and **kernel-hypervisor-fuzzing-ai**.

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

Build a detection-oriented lab without writing offensive code.

1. Create an isolated VM snapshot. Do not connect it to production networks.
2. Read the `ebpfkit` README and talk slides and list each feature, its program type and its helper, as in the table above.
3. On the clean VM, record baselines: `sudo bpftool prog show -j > progs.json`, `sudo bpftool map show -j > maps.json`, `sudo bpftool link show -j > links.json`, `ls -la /sys/fs/bpf`, `ss -0 -p`.
4. Install a benign eBPF tool such as `bpftrace` running an `execve` tracer and record the diff against the baseline. This is what "new program loaded" looks like.
5. Run `sudo dmesg | grep -i bpf` and check for helper warnings; note that a benign tracer produces none.

## Common pitfalls

- Hunting for eBPF rootkits only with user-space tools they can lie to.
- Assuming eBPF malware must use `bpf_probe_write_user`; network-only implants may not.
- Ignoring uprobes on crypto libraries.
- Treating `ebpfkit` features as the full space of possibilities.
- Running research PoCs on shared or production systems.

## Exercises

1. Map each capability in the table to at least one independent observation channel (kernel log, auditd, network tap, memory forensics).
2. List the syscalls a hiding implant must intercept to stay invisible to `ps`, `ls` and `bpftool`, and how you would cross-check each.
3. Hunt for packet sockets and attached classic BPF filters on a lab host with `ss -0 -p` and `sudo ss -0 --bpf`, and explain each one found.

## Further reading

- P. Hogan, "Warping Reality: Creating and Countering the Next Generation of Linux Rootkits Using eBPF", DEF CON 29 (2021)
- G. Fournier, S. Afchain, S. Baubeau, "eBPF, I thought we were friends!", DEF CON 29 (2021); `ebpfkit-monitor`: <https://github.com/Gui774ume/ebpfkit-monitor>
- J. Dileo, "Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime", DEF CON 27 (2019)
- Risky Business, "BPF malware is now...": <https://www.risky.biz/risky-biz-news-bpf-malware-is-now/>
- Datadog Security Labs, "Detection primitives for eBPF rootkits": <https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/>
- Related books: **onchain-malware-analysis**, **kernel-hypervisor-fuzzing-ai**
