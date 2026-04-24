# ⚛️ TorusGuard

**The Sovereign Shield for the Decentralized Web.**

TorusGuard is a next-generation security and privacy toolkit for Web3 developers and power users. It addresses critical real-world vulnerabilities identified in modern blockchain ecosystems (Ethereum, Solana, Neo3).

## 🛡️ Three Problems. One Shield.

### 1. Metadata Leakage (Privacy Proxy)
Every RPC call you make leaks your IP, user-agent, and timing. TorusGuard's **Privacy Proxy** wraps your Web3 calls and routes them through Tor with circuit rotation and jitter, ensuring your off-chain footprint is as anonymous as your on-chain one.

### 2. Quantum Vulnerability (Audit Scanner)
Most smart contracts use ECDSA (secp256k1/r1) which is broken by Shor's algorithm. Our **Quantum Scanner** performs static analysis on Solidity and Python (Neo3) contracts to identify vulnerable crypto-primitives and provides a migration path to Post-Quantum Cryptography (PQC).

### 3. Opaque Cross-Chain Compliance (ZK-Proofs)
Bridges are the weakest link. TorusGuard generates **ZK-Compliance Proofs** that attest to a transaction's legality (AML/Sanctions cleared) without revealing the sender's identity, enabling private yet compliant cross-chain value flow.

## 🚀 Getting Started

```bash
# Run the CLI tool
python3 cli.py scan ./contracts
python3 cli.py proxy --rotate 5
python3 cli.py prove --sender 0x123...
```

---
*Built with passion by ZoraX for the TOR DAO community.*