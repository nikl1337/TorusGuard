"""
Quantum Vulnerability Scanner — Static analysis for non-quantum-resistant algorithms.

Problem: Current smart contracts rely on ECDSA (SECP256k1/SECP256r1) for signatures,
keccak256 for hashing, and other algorithms vulnerable to Shor's/Grover's algorithms.
When quantum computers reach ~4000 logical qubits, these are broken.

Solution: TorusGuard scans Solidity and Python (Neo3/boa) contract source code,
identifying usage of vulnerable cryptographic primitives and suggesting
quantum-resistant alternatives (CRYSTALS-Dilithium, SPHINCS+, etc.).
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Language(Enum):
    SOLIDITY = "solidity"
    PYTHON = "python"
    UNKNOWN = "unknown"


@dataclass
class VulnerabilityPattern:
    name: str
    pattern: str  # regex
    severity: Severity
    description: str
    quantum_threat: str
    recommendation: str
    applies_to: list[Language]
    cwe_id: Optional[str] = None


@dataclass
class Finding:
    pattern_name: str
    severity: Severity
    line_number: int
    line_content: str
    description: str
    quantum_threat: str
    recommendation: str
    file_path: str = ""
    cwe_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern_name,
            "severity": self.severity.value,
            "line": self.line_number,
            "code": self.line_content.strip(),
            "description": self.description,
            "quantum_threat": self.quantum_threat,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    file_path: str
    language: Language
    total_lines: int
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: float = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def quantum_risk_score(self) -> str:
        score = 100
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score -= 25
            elif f.severity == Severity.HIGH:
                score -= 15
            elif f.severity == Severity.MEDIUM:
                score -= 8
            elif f.severity == Severity.LOW:
                score -= 3
        score = max(0, score)
        if score >= 80:
            return f"🟢 Low Risk ({score}/100)"
        elif score >= 50:
            return f"🟡 Medium Risk ({score}/100)"
        else:
            return f"🔴 High Risk ({score}/100)"

    def to_dict(self) -> dict:
        return {
            "file": self.file_path,
            "language": self.language.value,
            "lines_scanned": self.total_lines,
            "quantum_risk_score": self.quantum_risk_score,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "scan_time_ms": round(self.scan_time_ms, 2),
            "findings": [f.to_dict() for f in self.findings],
        }


# Vulnerability pattern database
VULNERABILITY_PATTERNS: list[VulnerabilityPattern] = [
    # ECDSA / SECP256k1
    VulnerabilityPattern(
        name="ECDSA-SECP256K1",
        pattern=r"(?i)(secp256k1|ecdsa|ecrecover|ECDSA\.recover|SignatureChecker)",
        severity=Severity.CRITICAL,
        description="Uses ECDSA with SECP256k1 curve — broken by Shor's algorithm",
        quantum_threat="Shor's algorithm can solve ECDLP in polynomial time on a quantum computer with ~2330 logical qubits",
        recommendation="Migrate to CRYSTALS-Dilithium (NIST PQC standard) or SPHINCS+ for signatures",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-327",
    ),
    VulnerabilityPattern(
        name="ECDSA-SECP256R1",
        pattern=r"(?i)(secp256r1|P-256|prime256v1|NIST\s*P.256)",
        severity=Severity.CRITICAL,
        description="Uses SECP256r1 (P-256) curve — equally vulnerable to quantum attacks",
        quantum_threat="Same ECDLP vulnerability as SECP256k1 under Shor's algorithm",
        recommendation="Replace with CRYSTALS-Dilithium or Falcon for post-quantum signatures",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-327",
    ),
    # RSA
    VulnerabilityPattern(
        name="RSA-USAGE",
        pattern=r"(?i)(RSA|rsa_sign|rsa_verify|RSA\.generate|PKCS1_v1_5|PKCS1_OAEP)",
        severity=Severity.CRITICAL,
        description="Uses RSA — broken by Shor's algorithm for integer factorization",
        quantum_threat="RSA-2048 requires ~4098 logical qubits to break; RSA-4096 requires ~8194",
        recommendation="Replace with CRYSTALS-Kyber (KEM) or CRYSTALS-Dilithium (signatures)",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-327",
    ),
    # Keccak/SHA (Grover's)
    VulnerabilityPattern(
        name="KECCAK256-WEAK",
        pattern=r"(?i)(keccak256|sha3_256|abi\.encodePacked.*keccak)",
        severity=Severity.MEDIUM,
        description="Uses Keccak256 — security halved by Grover's algorithm",
        quantum_threat="Grover's algorithm reduces 256-bit hash security to 128-bit equivalent",
        recommendation="Consider SHA-384 or SHA-512 for future-proofing (effectively 192/256 bit post-quantum)",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-328",
    ),
    VulnerabilityPattern(
        name="SHA256-GROVER",
        pattern=r"(?i)(sha256|SHA-256|hashlib\.sha256|sha2)",
        severity=Severity.MEDIUM,
        description="SHA-256 security reduced to ~128-bit by Grover's algorithm",
        quantum_threat="Grover's provides quadratic speedup for preimage attacks",
        recommendation="Upgrade to SHA-384+ or use hash-based signatures (SPHINCS+)",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-328",
    ),
    # EdDSA / Ed25519
    VulnerabilityPattern(
        name="ED25519-VULNERABLE",
        pattern=r"(?i)(ed25519|curve25519|Ed25519|nacl\.signing|tweetnacl)",
        severity=Severity.CRITICAL,
        description="Ed25519 relies on elliptic curve DLP — broken by quantum computers",
        quantum_threat="Same class of vulnerability as SECP256k1 under Shor's algorithm",
        recommendation="Migrate to CRYSTALS-Dilithium or hybrid Ed25519+Dilithium scheme",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
        cwe_id="CWE-327",
    ),
    # Solidity-specific
    VulnerabilityPattern(
        name="ECRECOVER-SOLIDITY",
        pattern=r"ecrecover\s*\(",
        severity=Severity.CRITICAL,
        description="Solidity ecrecover() uses SECP256k1 ECDSA — quantum-vulnerable",
        quantum_threat="Core Ethereum signature verification will be broken by quantum computers",
        recommendation="Use account abstraction (ERC-4337) with quantum-resistant signature schemes",
        applies_to=[Language.SOLIDITY],
        cwe_id="CWE-327",
    ),
    VulnerabilityPattern(
        name="SIGNATURE-VERIFY",
        pattern=r"(?i)(\.recover\(|isValidSignature|_checkSignature|verifySignature)",
        severity=Severity.HIGH,
        description="Custom signature verification likely using ECDSA",
        quantum_threat="If built on ECDSA, this verification will be breakable",
        recommendation="Prepare migration path to ERC-4337 abstract accounts with PQC",
        applies_to=[Language.SOLIDITY, Language.PYTHON],
    ),
    # Python-specific crypto imports
    VulnerabilityPattern(
        name="PYTHON-ECDSA-IMPORT",
        pattern=r"(?i)(from\s+ecdsa\s+import|import\s+ecdsa|from\s+cryptography.*ec\s+import)",
        severity=Severity.CRITICAL,
        description="Imports ECDSA library — all operations are quantum-vulnerable",
        quantum_threat="Entire ECDSA key generation, signing, and verification broken by Shor's",
        recommendation="Use oqs-python (liboqs) for post-quantum cryptography",
        applies_to=[Language.PYTHON],
        cwe_id="CWE-327",
    ),
    VulnerabilityPattern(
        name="WEB3-ACCOUNT-SIGN",
        pattern=r"(?i)(w3\.eth\.account\.sign|Account\.sign|eth_account\.sign)",
        severity=Severity.HIGH,
        description="Web3.py account signing uses SECP256k1",
        quantum_threat="Transaction signatures will be forgeable with quantum computers",
        recommendation="Wrap signing with TorusGuard privacy proxy + prepare PQC migration",
        applies_to=[Language.PYTHON],
    ),
    # Neo3/boa
    VulnerabilityPattern(
        name="NEO3-VERIFY",
        pattern=r"(?i)(CheckSig|CheckMultiSig|Neo\.Crypto\.VerifyWithECDsa|verify_with_ecdsa)",
        severity=Severity.CRITICAL,
        description="Neo3 contract uses ECDSA verification — quantum-vulnerable",
        quantum_threat="Neo3's default neoFS and contract verification uses SECP256r1",
        recommendation="Monitor Neo3 quantum-resistance roadmap; implement hybrid verification",
        applies_to=[Language.PYTHON, Language.SOLIDITY],
    ),
    # DH / Key Exchange
    VulnerabilityPattern(
        name="DIFFIE-HELLMAN",
        pattern=r"(?i)(diffie.hellman|DH_generate|ECDH|key_exchange|generate_dh|dh\.generate)",
        severity=Severity.CRITICAL,
        description="Diffie-Hellman key exchange — broken by quantum computing",
        quantum_threat="Both classical DH and ECDH broken by Shor's algorithm",
        recommendation="Use CRYSTALS-Kyber for key encapsulation (NIST PQC standard)",
        applies_to=[Language.PYTHON, Language.SOLIDITY],
        cwe_id="CWE-327",
    ),
    # Private key handling
    VulnerabilityPattern(
        name="PRIVATE-KEY-EXPOSURE",
        pattern=r"(?i)(private.key|privateKey|secret.key|signing.key)\s*=\s*['\"]",
        severity=Severity.HIGH,
        description="Hardcoded private key detected",
        quantum_threat="Private keys on vulnerable curves can be derived from public keys with quantum computers",
        recommendation="Use HSM/TEE for key storage; never hardcode keys",
        applies_to=[Language.PYTHON, Language.SOLIDITY],
        cwe_id="CWE-798",
    ),
]


class QuantumScanner:
    """Static analysis scanner for quantum-vulnerable cryptographic patterns."""

    def __init__(self, custom_patterns: Optional[list[VulnerabilityPattern]] = None):
        self.patterns = VULNERABILITY_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def detect_language(self, file_path: str, content: str) -> Language:
        if file_path.endswith(".sol"):
            return Language.SOLIDITY
        elif file_path.endswith(".py"):
            return Language.PYTHON
        # Try content-based detection
        if "pragma solidity" in content or "contract " in content:
            return Language.SOLIDITY
        if "import " in content or "def " in content:
            return Language.PYTHON
        return Language.UNKNOWN

    def scan_content(self, content: str, file_path: str = "<stdin>") -> ScanResult:
        import time as _time

        start = _time.time()
        language = self.detect_language(file_path, content)
        lines = content.split("\n")
        findings: list[Finding] = []

        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                continue

            for pat in self.patterns:
                if language != Language.UNKNOWN and language not in pat.applies_to:
                    continue
                if re.search(pat.pattern, line):
                    findings.append(
                        Finding(
                            pattern_name=pat.name,
                            severity=pat.severity,
                            line_number=i,
                            line_content=line,
                            description=pat.description,
                            quantum_threat=pat.quantum_threat,
                            recommendation=pat.recommendation,
                            file_path=file_path,
                            cwe_id=pat.cwe_id,
                        )
                    )

        elapsed_ms = (_time.time() - start) * 1000
        return ScanResult(
            file_path=file_path,
            language=language,
            total_lines=len(lines),
            findings=findings,
            scan_time_ms=elapsed_ms,
        )

    def scan_file(self, file_path: str) -> ScanResult:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.scan_content(content, file_path)

    def scan_directory(self, dir_path: str, extensions: Optional[list[str]] = None) -> list[ScanResult]:
        import os

        extensions = extensions or [".sol", ".py"]
        results = []
        for root, _, files in os.walk(dir_path):
            for fname in sorted(files):
                if any(fname.endswith(ext) for ext in extensions):
                    fpath = os.path.join(root, fname)
                    results.append(self.scan_file(fpath))
        return results

    @staticmethod
    def format_report(results: list[ScanResult]) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("  ⚛️  TORUSGUARD QUANTUM VULNERABILITY REPORT")
        lines.append("=" * 70)
        lines.append("")

        total_findings = sum(len(r.findings) for r in results)
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)

        lines.append(f"  Files scanned:     {len(results)}")
        lines.append(f"  Total findings:    {total_findings}")
        lines.append(f"  Critical:          {total_critical}")
        lines.append(f"  High:              {total_high}")
        lines.append("")

        for result in results:
            if not result.findings:
                continue
            lines.append("-" * 70)
            lines.append(f"  📄 {result.file_path}")
            lines.append(f"     Language: {result.language.value} | Lines: {result.total_lines}")
            lines.append(f"     Quantum Risk: {result.quantum_risk_score}")
            lines.append("")

            for f in sorted(result.findings, key=lambda x: x.severity.value):
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪️"}.get(
                    f.severity.value, "⚪️"
                )
                lines.append(f"     {icon} [{f.severity.value}] Line {f.line_number}: {f.pattern_name}")
                lines.append(f"        Code: {f.line_content.strip()[:80]}")
                lines.append(f"        Threat: {f.quantum_threat[:80]}")
                lines.append(f"        Fix: {f.recommendation[:80]}")
                if f.cwe_id:
                    lines.append(f"        Ref: {f.cwe_id}")
                lines.append("")

        lines.append("=" * 70)
        lines.append("  🔮 Post-Quantum Migration Guide:")
        lines.append("     • Signatures: CRYSTALS-Dilithium / SPHINCS+ / Falcon")
        lines.append("     • Key Exchange: CRYSTALS-Kyber")
        lines.append("     • Hashing: SHA-384+ (128-bit post-quantum security)")
        lines.append("     • Ethereum: ERC-4337 Account Abstraction for PQC sigs")
        lines.append("     • Reference: NIST SP 800-208, FIPS 203/204/205")
        lines.append("=" * 70)
        return "\n".join(lines)