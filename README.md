# eBPF Security: Tooling and Threats

> eBPF-based detection, eBPF rootkits, verifier trust and hardening the kernel's programmable layer.

## Contents

<!-- toc:start -->
1. [eBPF as Sensor and Attack Surface: Problem and Threat Model](chapters/01-problem-and-threat-model.md)
2. [eBPF Architecture: Verifier, JIT, Maps, Helpers and Program Types](chapters/02-architecture-verifier-maps-helpers.md)
3. [Defensive Tooling: Falco, Tetragon, Tracee and Their Limits](chapters/03-defensive-tooling.md)
4. [Offensive Abuse of eBPF in Public Research](chapters/04-offensive-abuse-in-public-research.md)
5. [Detecting Malicious BPF Programs](chapters/05-detecting-malicious-bpf.md)
6. [Hardening the Programmable Kernel: Checklist and Research Directions](chapters/06-hardening-checklist-and-research.md)
<!-- toc:end -->

## How to read this

Read chapters in order, or jump to what you need. Every chapter ends with exercises and further reading. See [RESOURCES.md](RESOURCES.md) and [GLOSSARY.md](GLOSSARY.md).

## Build

```bash
mdbook serve   # optional: renders SUMMARY.md as a website
```

## License

Text: CC BY-SA 4.0. Code snippets: MIT. See [LICENSE](LICENSE).
