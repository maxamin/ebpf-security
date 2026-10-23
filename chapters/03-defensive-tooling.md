# Defensive Tooling: Falco, Tetragon, Tracee and Their Limits

Most open-source Linux runtime security tools now collect events through eBPF. This chapter compares three widely used projects, explains how they hook the kernel, and covers the known ways their view of the system can be wrong. Check each project's current documentation before deploying, because drivers, defaults and policy formats change between releases.

## The three tools

**Falco** (CNCF graduated project, started by Sysdig) evaluates rules written in YAML against a stream of system call and plugin events. Its documentation lists two kernel drivers: the modern eBPF probe, which is the default and is bundled into the Falco binary (`engine.kind: modern_ebpf`), and a kernel module that requires full privileges. Older releases also shipped a legacy eBPF probe; check whether your version still supports it. Andres Pihlak's 2020 master's thesis at Tallinn University of Technology ("Continuous Docker Image Analysis and Intrusion Detection Based on Open-Source Tools") is a useful local example of integrating Falco into a container pipeline, describing how it uses syscall instrumentation to detect abnormal activity in applications, containers and the host according to a rule set.

**Tetragon** (Cilium project, Isovalent) loads eBPF programs defined by `TracingPolicy` custom resources. Policies select kprobes, tracepoints, uprobes or LSM hooks, filter arguments in the kernel, and can enforce. Its documentation describes two in-kernel enforcement methods: overriding a function's return value and sending a signal such as SIGKILL. It warns that SIGKILL alone does not guarantee an operation fails, since a `write()` may complete before the process dies, and recommends combining Sigkill with Override where the hook supports it.

**Tracee** (Aqua Security) traces events through eBPF and evaluates signatures. Its architecture separates event collection from a rule engine; signatures can be written in Go or Rego. It also offers raw tracing for forensics.

| Feature | Falco | Tetragon | Tracee |
|---|---|---|---|
| Primary input | Syscalls (plus plugins: Kubernetes audit, cloud logs) | Policy-defined kprobes, tracepoints, LSM hooks | Syscalls and kernel events |
| Rule language | YAML conditions | `TracingPolicy` CRD (YAML) | Go / Rego signatures |
| In-kernel filtering | Limited (driver filters) | Yes, central design goal | Partial |
| Enforcement | Alerting; response via external tooling | Override and signal actions in kernel | Primarily detection |
| Kubernetes awareness | Yes | Yes (pod/namespace selectors) | Yes |

## What eBPF sensors see well

Process execution with full ancestry, file opens on sensitive paths, network connections per process and container, privilege changes, kernel module loading, and `bpf()` calls themselves. Fournier's Black Hat USA 2022 talk "Return to Sender: Detecting Kernel Exploits with eBPF" (KRIe) went further, using eBPF to check kernel runtime integrity: watching for execution-flow redirection, logic-bug exploitation and post-compromise alterations of kernel state. The same talk listed why this is hard: "there are dozens of ways to disable an eBPF program", post-compromise detection is "fighting a lost battle", and in-kernel monitoring has a performance cost. Its stated value was raising the bar against commodity rootkits and detecting some attacks before compromise completes.

## Known blind spots

**TOCTOU in syscall argument capture.** Rex Guo and Junyuan Zeng's work ("Phantom Attack: Evading System Call Monitoring", DEF CON 29, and "Trace Me If You Can: Bypassing Linux Syscall Tracing", Black Hat USA 2022) showed that a tracer reading a user-space pointer at syscall entry (time of check) may see different data from what the kernel later copies (time of use). A racing thread can change a file name or socket address in between. The talk used Falco's tracepoint-based drivers as a case study. Mitigations include hooking after the kernel has copied arguments (for example LSM hooks or kernel functions that receive kernel copies) and correlating entry and exit events.

**Hook coverage.** Programs attached to a syscall miss equivalent paths: `openat2` versus `open`, io_uring operations that bypass the classic syscall path, and new syscalls added after rules were written.

**Self-protection.** A root attacker can detach programs, delete maps, kill the agent, or load programs that tamper with the agent's user-space reads. Elastic publishes a detection rule for bpftool commands that detach programs or modify maps, a sign that tampering is expected.

**Event loss.** Ring buffers overflow under load. Attackers can generate noise to cause drops. Monitor the agent's own drop counters.

## Deployment guidance

- Run the agent with the minimum capabilities its driver supports, and isolate it from untrusted workloads.
- Ship events off-host immediately so a later compromise cannot erase them.
- Alert on agent health: heartbeats, drop rates, program detachment.
- Prefer LSM or post-copy hooks for security-critical decisions.
- Version-control rules and policies; test them in CI against recorded events.

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

Deploy Tetragon in a local kind or minikube cluster and observe a policy.

1. Create a cluster and install Tetragon with Helm following the project's getting-started guide.
2. Stream events: `kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact`.
3. Start a test pod and run `cat /etc/shadow` inside it. Observe the process execution event.
4. Apply the documentation's file-monitoring example `TracingPolicy` and repeat. Confirm a kprobe event for the file access appears.
5. Install Falco with its default rules in the same cluster and compare which tool alerts first and with what context.

## Common pitfalls

- Relying on syscall-entry argument values for security decisions.
- Deploying SIGKILL enforcement without understanding that the operation may already have taken effect.
- Not monitoring the monitoring: no alert when the agent stops.
- Writing rules for `open` but not `openat`, `openat2` or io_uring.
- Running Falco, Tetragon and Tracee together without testing overhead and event loss.

## Exercises

1. Write a Falco rule and a Tetragon policy that both detect reads of `/etc/shadow` by non-allowlisted binaries, and compare false positives over a day of lab activity.
2. Generate heavy syscall load with `stress-ng` and measure each tool's dropped-event counters.
3. Reproduce the idea of the TOCTOU issue in a lab using the public description: find which of your rules read user pointers at syscall entry.

## Further reading

- Falco kernel event sources: <https://falco.org/docs/concepts/event-sources/kernel/>
- Tetragon enforcement concepts: <https://tetragon.cilium.io/docs/concepts/enforcement/>
- Tracee documentation: <https://aquasecurity.github.io/tracee/>
- G. Fournier, "Return to Sender: Detecting Kernel Exploits with eBPF", Black Hat USA 2022 (KRIe)
- R. Guo, J. Zeng, "Trace Me If You Can: Bypassing Linux Syscall Tracing", Black Hat USA 2022; "Phantom Attack", DEF CON 29
- A. Pihlak, "Continuous Docker Image Analysis and Intrusion Detection Based on Open-Source Tools", MSc thesis, Tallinn University of Technology, 2020
- Related books: **ai-driven-threat-hunting**
