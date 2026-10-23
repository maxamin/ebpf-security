# Glossary

- **eBPF:** extended Berkeley Packet Filter; an in-kernel virtual machine running verified programs attached to kernel and user-space hooks.
- **Classic BPF (cBPF):** the original packet-filter bytecode used by `tcpdump` and socket filters.
- **Verifier:** kernel component that statically checks every path of an eBPF program for memory safety and termination before loading.
- **JIT:** just-in-time compiler translating eBPF bytecode into native machine code.
- **Constant blinding:** JIT hardening that XORs immediate constants with random values to prevent JIT spraying.
- **Map:** kernel data structure shared between eBPF programs and user space.
- **Helper:** kernel function an eBPF program may call; availability depends on program type.
- **kfunc:** kernel function explicitly exported for BPF programs, newer alternative to helpers.
- **Program type:** category such as kprobe, tracepoint, XDP, tc, LSM, defining hooks and helpers available.
- **kprobe / uprobe:** dynamic probes on kernel / user-space function entry or return.
- **XDP:** eXpress Data Path; eBPF hook at the network driver level, before the kernel network stack.
- **BPF LSM (KRSI):** program type attaching eBPF to Linux Security Module hooks to audit or deny operations.
- **CO-RE / BTF:** compile once, run everywhere, using BPF Type Format metadata to relocate struct offsets at load time.
- **bpffs:** pseudo-filesystem (usually `/sys/fs/bpf`) used to pin BPF objects so they outlive their loader.
- **BPF token:** kernel 6.9+ mechanism delegating limited BPF privileges to a user namespace.
- **CAP_BPF:** Linux capability (5.8+) for BPF operations separate from `CAP_SYS_ADMIN`.
- **Program tag:** hash of a program's instructions reported by `bpftool`, useful for allowlisting.
- **TOCTOU:** time-of-check to time-of-use race; here, a tracer reading syscall arguments before the kernel does.
