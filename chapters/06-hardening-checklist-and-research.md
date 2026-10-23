# Hardening the Programmable Kernel: Checklist and Research Directions

eBPF cannot simply be switched off on most modern hosts, because networking, observability and security agents depend on it. Hardening means restricting who can load what, reducing the kernel attack surface exposed through the verifier, making loaded programs attributable, and keeping an independent view for detection. This chapter collects the controls and ends with a checklist and open research questions.

## Control 1: unprivileged BPF

The `kernel.unprivileged_bpf_disabled` sysctl controls whether users without privileges can call `bpf()`. The kernel documentation defines three values: `0` enables unprivileged calls; `1` disables them "without recovery" (once set, it cannot be cleared on the running kernel); `2` disables them but lets an administrator change the setting later. Kernels built with `CONFIG_BPF_UNPRIV_DEFAULT_OFF` default to `2`, which most major distributions now ship.

Recommendation: set `1` on servers that do not need unprivileged BPF, in an early boot sysctl file, so that a later root compromise cannot quietly re-enable it.

## Control 2: capabilities and delegation

Since kernel 5.8, `CAP_BPF` separates BPF privileges from `CAP_SYS_ADMIN`. Tracing programs also need `CAP_PERFMON`; networking programs need `CAP_NET_ADMIN`. In practice, many agents still run with `CAP_SYS_ADMIN`. Audit which containers and services hold these capabilities, and never grant them to general workloads.

BPF tokens, introduced in kernel 6.9, allow a privileged parent to delegate a restricted set of BPF commands, program types and attach types to a user namespace through a specially mounted bpffs; the kernel checks the token rather than the caller's ordinary credentials. LXD and Incus document using tokens to let containers run specific BPF workloads. Tokens are safer than handing a container `CAP_SYS_ADMIN`, but each delegated program type still exposes the verifier to that container, so delegate as narrowly as possible.

## Control 3: BPF LSM and policy on loads

With `CONFIG_BPF_LSM=y` and `bpf` in the `lsm=` boot parameter, eBPF programs can attach to LSM hooks, including hooks that fire on `bpf()` operations themselves. That allows policies such as "only these binaries, verified by path and ideally by integrity measurement, may load programs" or "deny `bpf_probe_write_user`-using programs". SELinux and AppArmor also have BPF-related permissions.

## Control 4: signed programs

Upstream kernel work added BPF program signing; Phoronix reported initial support queued for Linux 6.18 in 2025, and the kernel's "BPF signing" documentation describes a PKCS#7 check over the instructions and any bound map metadata. Per that documentation, the kernel does not require signatures by itself; it records a verdict that an LSM can enforce, and a valid signature establishes origin and integrity, not safety. Treat signing as a building block for "only our vendor-signed agents may load programs", enforced through an LSM policy, and check the current kernel documentation for your version.

## Control 5: lockdown, JIT and kernel config

- Kernel lockdown in `integrity` or `confidentiality` mode restricts some BPF features that read kernel memory (for example `bpf_probe_read_kernel` in confidentiality mode). Test agents under lockdown before enforcing.
- Set `net.core.bpf_jit_harden=2` where performance allows, to blind constants for all users, and build with `CONFIG_BPF_JIT_ALWAYS_ON`.
- Disable `CONFIG_BPF_KPROBE_OVERRIDE` if no tool needs `bpf_override_return`.
- Patch promptly: verifier fixes ship in stable kernels, and distribution kernels may lag.

## Control 6: detection independence

Hardening will not stop an attacker who already has root and full BPF privileges. Keep detection channels the attacker cannot easily filter: off-host kernel logs, auditd rules on `bpf()`, network flow data from outside the host, periodic memory acquisition on high-value systems, and BPF inventories compared across hosts.

## Checklist

- [ ] `kernel.unprivileged_bpf_disabled=1` on servers; documented exceptions.
- [ ] Inventory of every process and container with `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` or `CAP_SYS_ADMIN`.
- [ ] BPF tokens used instead of broad capabilities where delegation is needed, scoped to specific program types.
- [ ] BPF LSM enabled; policy restricting program loads to approved loaders.
- [ ] Program signing evaluated for your kernel version and agent vendors.
- [ ] `bpf_jit_harden` set; JIT always on; unused BPF features disabled in kernel config.
- [ ] Baseline `bpftool` inventory per host role, diffed on a schedule; ID-walk check included.
- [ ] auditd rule for `bpf()`; alerts on loads outside allowlist and on bpftool detach/delete.
- [ ] Kernel logs shipped off-host; alerts on BPF helper warnings.
- [ ] Security agents monitored for health, drops and detachment.
- [ ] Verifier CVE tracking and kernel patch SLA.
- [ ] Incident runbook includes eBPF objects, pinned paths and memory acquisition.

## Research directions

Open questions in public work: making verifier correctness more provable (formal verification of range tracking, differential testing of verifier and JIT, as fuzzing research in **kernel-hypervisor-fuzzing-ai** explores); trustworthy attestation of which BPF programs are loaded, for example reporting signed program hashes to a remote verifier; detection that does not depend on the same kernel facilities an implant can hook; safe delegation models for multi-tenant clusters; and the security of eBPF on other platforms, such as Microsoft's eBPF for Windows, whose attack surface Richard Johnson examined in "eBPF ELFs JMPing Through the Windows" (Black Hat USA 2022).

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

Harden a lab VM and verify each control.

1. Create `/etc/sysctl.d/10-bpf.conf` with `kernel.unprivileged_bpf_disabled = 1` and `net.core.bpf_jit_harden = 2`; reboot and confirm with `sysctl`.
2. As an unprivileged user, run `bpftool prog show`; expect a permission error.
3. Add `lsm=...,bpf` to the kernel command line (append `bpf` to the existing list from `/sys/kernel/security/lsm`), reboot and confirm `bpf` appears in the list.
4. Deploy a Tetragon or custom LSM policy that alerts on program loads by anything other than your agent and `bpftool`; test by running `bpftrace`.
5. Record which agents broke and why; adjust the allowlist rather than removing the control.

## Common pitfalls

- Setting the sysctl to `2` and assuming it cannot be reverted by root.
- Granting `CAP_SYS_ADMIN` to an observability DaemonSet because it is easier.
- Enabling signing verification without an LSM policy that enforces the verdict.
- Locking down hosts without testing the security agent first.
- Treating eBPF hardening as a one-time task rather than following each kernel release.

## Exercises

1. Write a Kubernetes admission policy (Kyverno or OPA Gatekeeper) that rejects pods requesting `CAP_BPF` or `CAP_SYS_ADMIN` outside an approved namespace.
2. Set up BPF token delegation for one container in LXD or Incus and document exactly which program types are allowed.
3. Draft a one-page eBPF incident runbook using the checklist and the detection layers from Chapter 5.

## Further reading

- Kernel sysctl documentation (`unprivileged_bpf_disabled`, `bpf_stats_enabled`): <https://docs.kernel.org/admin-guide/sysctl/kernel.html>
- Kernel BPF signing documentation: <https://docs.kernel.org/bpf/signing.html>
- Canonical LXD, "Privilege delegation using BPF Token": <https://canonical.com/lxd/docs/latest/explanation/bpf/>
- Phoronix, "BPF With Linux 6.18 To Support Signed Programs": <https://www.phoronix.com/news/Linux-6.18-BPF-Signed-Deferred>
- R. Johnson, "eBPF ELFs JMPing Through the Windows", Black Hat USA 2022
- Related books: **kernel-hypervisor-fuzzing-ai**, **validator-operations-security**
