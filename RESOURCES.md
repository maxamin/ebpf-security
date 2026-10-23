# Resources

## Documentation

- eBPF overview and project list: <https://ebpf.io>
- Linux kernel BPF documentation: <https://docs.kernel.org/bpf/>
- Kernel sysctl documentation (`unprivileged_bpf_disabled`, `bpf_stats_enabled`): <https://docs.kernel.org/admin-guide/sysctl/kernel.html>
- BPF signing: <https://docs.kernel.org/bpf/signing.html>
- BPF token delegation (LXD): <https://canonical.com/lxd/docs/latest/explanation/bpf/>

## Defensive tools

- Falco: <https://falco.org>; kernel drivers: <https://falco.org/docs/concepts/event-sources/kernel/>
- Tetragon: <https://tetragon.cilium.io>; enforcement: <https://tetragon.cilium.io/docs/concepts/enforcement/>
- Tracee: <https://aquasecurity.github.io/tracee/>
- bpftool (kernel tree `tools/bpf/bpftool`), bpftrace: <https://github.com/bpftrace/bpftrace>
- Elastic detection rule "BPF Program Tampering via bpftool": <https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/defense_evasion_bpf_program_tampering>
- Volatility 3: <https://github.com/volatilityfoundation/volatility3>

## Research talks and papers

- J. Dileo, "Evil eBPF: Practical Abuses of an In-Kernel Bytecode Runtime", DEF CON 27 (2019)
- G. Fournier, S. Afchain, S. Baubeau, "eBPF, I thought we were friends!", DEF CON 29 (2021)
- P. Hogan, "Warping Reality: Creating and Countering the Next Generation of Linux Rootkits Using eBPF", DEF CON 29 (2021)
- G. Fournier, "Return to Sender: Detecting Kernel Exploits with eBPF", Black Hat USA 2022
- R. Guo, J. Zeng, "Trace Me If You Can: Bypassing Linux Syscall Tracing", Black Hat USA 2022; "Phantom Attack: Evading System Call Monitoring", DEF CON 29
- E. Reshetova, F. Bonazzi, N. Asokan, "Randomization Can't Stop BPF JIT Spray", Black Hat Europe 2016
- R. Johnson, "eBPF ELFs JMPing Through the Windows", Black Hat USA 2022
- Datadog Security Labs, "Detection primitives for eBPF rootkits": <https://securitylabs.datadoghq.com/articles/detection-primitives-for-ebpf-rootkits/>

## Threat reports

- Trend Micro, "BPFDoor's Hidden Controller" (2025): <https://www.trendmicro.com/en_gb/research/25/d/bpfdoor-hidden-controller.html>
- Risky Business, BPF malware summary: <https://www.risky.biz/risky-biz-news-bpf-malware-is-now/>

## Related books in this wiki

- **kernel-hypervisor-fuzzing-ai** (verifier fuzzing), **ai-driven-threat-hunting**
