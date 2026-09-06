markdown
# 🔐 Cryptographic Libraries

> A robust, audited C library of cryptographic primitives built specifically for blockchain applications.

[![CI Status](https://img.shields.io/github/actions/workflow/status/Gitdigital-products/Cryptographic-Libraries/ci.yml?branch=main&label=CI&logo=github)](https://github.com/Gitdigital-products/Cryptographic-Libraries/actions)
[![License](https://img.shields.io/github/license/Gitdigital-products/Cryptographic-Libraries)](LICENSE)
[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Security](https://img.shields.io/badge/security-audited-brightgreen)](AUDIT.md)
[![TDD](https://img.shields.io/badge/development-TDD-5B6ADF)](https://en.wikipedia.org/wiki/Test-driven_development)
[![Fuzzing](https://img.shields.io/badge/testing-fuzzing-orange)](#)
[![Constant Time](https://img.shields.io/badge/crypto-constant--time-critical)](#)
[![HACL](https://img.shields.io/badge/verification-HACL*-blueviolet)](https://project-everest.github.io/)

---

## 📦 Tags / Topics
`crypto` · `blockchain` · `sha256` · `hash` · `security` · `tdd` · `audited` · `c-library` · `constant-time` · `side-channel-resistant`

---

## 📖 About

This repository provides **secure and performant** cryptographic building blocks for distributed ledger technologies. Developed using **Test-Driven Development (TDD)** and incorporating **formal verification methods** (e.g., HACL\*), the library ensures reliability at the protocol level.

**Key Design Principles:**
- 🛡️ **Constant-time operations** to mitigate side-channel attacks.
- 🧠 **Secure memory management** (zeroization, protected allocators).
- ✅ **Known Answer Tests (KAT)** and **fuzzing** for edge-case validation.

---

## 📂 Core Structure

```bash
.
├── src/primitives/          # Core implementations (hash, signatures, etc.)
│   ├── hash/
│   │   ├── sha2.h
│   │   └── sha2.c
├── tests/                   # Unit tests, KAT, and Fuzzing harnesses
├── third_party/test_vectors # Official NIST / RFC test vectors
├── include/crypto_lib/      # Public API headers
├── .github/workflows/       # CI/CD automation
├── Makefile                 # Build & test orchestration
├── AUDIT.md                 # Security audit checklist
└── SECURITY.md              # Vulnerability disclosure policy
```

---

🚀 Build & Test

Build the library and run the full test suite:

```bash
make
make test
```

To run fuzzing targets (requires clang and libFuzzer):

```bash
make fuzz
```

---

🔬 Current Implementation Status

Primitive Status Verification
SHA-256 ✅ Complete KAT + Fuzzing
ECDSA 🚧 Planned -
EdDSA 🚧 Planned -
AES-GCM 🚧 Planned -

---

🤝 Contributing

We welcome contributions! Please read our Security Policy and check the Pull Request Template before submitting.

---

☕ Support the Development

If this library saves you time or helps secure your project, consider fueling future development with a donation. Every bit helps us maintain audits and expand features!

· 👤 Author (Rickcreator87): Donate via Cash App
· 🏢 Organization (GitDigital): Donate via Cash App

---

📄 License

Distributed under the LICENSE file in this repository.

```

---


