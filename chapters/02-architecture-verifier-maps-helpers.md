# eBPF Architecture: Verifier, JIT, Maps, Helpers and Program Types

Before you can defend eBPF or detect its abuse, you need a precise picture of how a program gets from source code to a running kernel hook, what it is allowed to touch, and where trust is placed along the way. This chapter walks through that pipeline.

## The load pipeline

1. **Compile.** Programs are written in restricted C (or Rust) and compiled by Clang/LLVM or GCC into eBPF bytecode inside an ELF object. Sections such as `SEC("tp/syscalls/sys_enter_execve")` name the intended hook.
2. **Load.** A user-space loader (usually via libbpf, sometimes Go or Rust libraries) creates maps and calls `bpf(BPF_PROG_LOAD, ...)` with the instructions, program type and license.
3. **Verify.** The in-kernel verifier simulates every path and rejects programs it cannot prove safe.
4. **JIT.** If accepted, the bytecode is translated into native machine code. Helper call sites are patched to real kernel addresses.
5. **Attach.** The program file descriptor is attached to a hook through a type-specific API (perf events, netlink for tc/XDP, `bpf_link`, cgroup attach).
6. **Run.** The program runs on each event and exchanges data with user space through maps and ring buffers.

Hogan's DEF CON 29 talk shows this concretely, including the verifier's annotated output where each C line is followed by its bytecode, and the same helper call that appears as `85 00 00 00 24 00 00 00` on disk becomes a relocated call in the kernel. The CO-RE ("compile once, run everywhere") approach with BTF type information lets one object run on many kernel versions by relocating field offsets at load time.

## What the verifier checks

The verifier is the core of eBPF's safety argument. Fournier, Afchain and Baubeau's DEF CON 29 slides list its main rules, which remain a good summary:

- the control-flow graph must be acyclic, except for loops the verifier can bound (supported since kernel 5.3);
- no unchecked pointer dereferences; every map lookup result must be NULL-checked;
- no unreachable instructions;
- stack limited to 512 bytes;
- a limit on the number of instructions the verifier will process (raised to one million for privileged programs in 5.2).

It tracks the type and value range of every register at every instruction: whether it holds a scalar, a pointer to the context, a map value, a packet, the stack, and what bounds apply. Pointer arithmetic is only allowed within known bounds.

This makes the verifier a large, subtle static analyser running in kernel context. When its range tracking is wrong, a program it accepts can read or write kernel memory out of bounds. Verifier bugs have repeatedly been turned into local privilege escalation; well-known examples include CVE-2020-8835 and CVE-2021-3490, both exploited at Pwn2Own contests. That is why unprivileged loading is now disabled by default on most distributions, and why the verifier is a prime fuzzing target (see **kernel-hypervisor-fuzzing-ai**).

## JIT hardening

JIT compilation puts attacker-influenced bytes into executable kernel memory. Reshetova, Bonazzi and Asokan's Black Hat Europe 2016 paper "Randomization Can't Stop BPF JIT Spray" showed that large numbers of crafted filters could place useful instruction sequences at predictable locations despite randomisation. The `net.core.bpf_jit_harden` sysctl enables constant blinding (constants are XOR-ed with random values so they cannot double as instructions), and `CONFIG_BPF_JIT_ALWAYS_ON` removes the interpreter, which had been abused in Spectre-variant gadgets.

## Maps

Maps are kernel data structures shared between programs and user space: hash tables, arrays, per-CPU variants, LRU maps, ring buffers, program arrays for tail calls, and more. Any process with a file descriptor to a map, or the privilege to obtain one by ID, can read and often write it. Security consequences:

- A detection agent's configuration map (for example its allowlist) is an integrity target.
- Maps pinned in `/sys/fs/bpf` persist while the loader exits and can be opened by path.
- Program arrays let one program jump to another with `bpf_tail_call`, which can split logic so no single program looks suspicious.

## Helpers and kfuncs

Programs cannot call arbitrary kernel functions. They call a fixed set of helpers, and newer kernels add "kfuncs" exported for BPF. The program type determines which helpers are allowed. Dileo's talk put it plainly: "the BPF helper functions do all of the heavy lifting". Helpers that matter most for security:

| Helper | Purpose | Abuse concern |
|---|---|---|
| `bpf_probe_read_kernel/user` | Read memory | Credential and secret harvesting |
| `bpf_probe_write_user` | Write to the current process's user memory | Tampering with syscall results; kernel logs a warning |
| `bpf_override_return` | Change return value of whitelisted functions (needs `CONFIG_BPF_KPROBE_OVERRIDE`) | Faking syscall failures |
| `bpf_send_signal` | Signal current task | Killing tools or analysts |
| `bpf_skb_store_bytes`, XDP adjust helpers | Modify packets | Hidden C2, traffic rewriting |

## Program types and hooks

Kernel 5.13 had around 30 program types; there are more now. The ones that matter most for security are tracing types (kprobe, tracepoint, raw tracepoint, fentry/fexit, uprobe), networking types (socket filter, tc/`sched_cls`, XDP, cgroup socket hooks) and `BPF_PROG_TYPE_LSM`, which attaches to Linux Security Module hooks and can deny operations. LSM programs are the basis of KRSI (kernel runtime security instrumentation) and of eBPF-based enforcement.

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

Trace the pipeline end to end on a lab VM.

1. Install `bpftrace` and `bpftool`. Run `sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s\n", str(args->filename)); }'`.
2. In another terminal, `sudo bpftool prog show` and find the new tracepoint program. Note its ID, tag and `map_ids`.
3. Dump its translated bytecode with `sudo bpftool prog dump xlated id <ID>` and the JIT output with `sudo bpftool prog dump jited id <ID>`.
4. Check `sudo bpftool btf show` and confirm BTF is available (`/sys/kernel/btf/vmlinux`).
5. Stop bpftrace and confirm the program disappears, showing it was not pinned.

## Common pitfalls

- Assuming the verifier is a security boundary against root; it protects kernel stability, not policy.
- Leaving `bpf_jit_harden` at 0 on hosts that permit any non-root BPF.
- Ignoring pinned maps and programs under `/sys/fs/bpf` during incident response.
- Treating program names as trustworthy; they are chosen by the loader.
- Forgetting that helper availability differs by kernel version and config.

## Exercises

1. Write a bpftrace one-liner that counts `bpf()` syscalls by command and process name, and run a tool such as `bpftool` to see the events.
2. Compare `bpftool feature probe` output on two kernels and list helpers present on one but not the other.
3. Read the verifier log (`bpftool prog load ... -d` or libbpf debug output) of a rejected program you write that dereferences a map value without a NULL check.

## Further reading

- Kernel BPF documentation: <https://docs.kernel.org/bpf/>
- E. Reshetova, F. Bonazzi, N. Asokan, "Randomization Can't Stop BPF JIT Spray", Black Hat Europe 2016
- J. Dileo, "Evil eBPF", DEF CON 27 (2019)
- G. Fournier, S. Afchain, S. Baubeau, "eBPF, I thought we were friends!", DEF CON 29 (2021)
- Richard Johnson, "eBPF ELFs JMPing Through the Windows", Black Hat USA 2022 (eBPF for Windows attack surface and fuzzing)
- Related books: **kernel-hypervisor-fuzzing-ai**
