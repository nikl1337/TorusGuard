import sys
import json
from torusguard.privacy_proxy import PrivacyProxy
from torusguard.quantum_scanner import QuantumScanner
from torusguard.zk_proof import ZKPrivacyProver, TransactionInput, ChainType, ComplianceLevel

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cli.py [proxy|scan|prove]")
        return

    cmd = sys.argv[1]

    if cmd == "proxy":
        proxy = PrivacyProxy("https://eth-mainnet.g.alchemy.com/v2/your-key")
        resp = proxy.send_rpc("eth_blockNumber")
        print(json.dumps(resp.to_dict(), indent=2))
        print("\nPrivacy Report:")
        print(json.dumps(proxy.get_privacy_report(), indent=2))

    elif cmd == "scan":
        scanner = QuantumScanner()
        # Scan a mock contract
        mock_contract = """
        contract Vulnerable {
            function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure {
                address signer = ecrecover(hash, v, r, s);
            }
        }
        """
        result = scanner.scan_content(mock_contract, "Vulnerable.sol")
        print(QuantumScanner.format_report([result]))

    elif cmd == "prove":
        prover = ZKPrivacyProver()
        tx = TransactionInput(
            sender_address="0xabc123...",
            receiver_address="0xdef456...",
            amount=10.5,
            token="ETH",
            source_chain=ChainType.ETHEREUM,
            destination_chain=ChainType.SOLANA,
            compliance_level=ComplianceLevel.ENHANCED
        )
        attestation = prover.generate_proof(tx)
        print("ZK Attestation Generated:")
        print(json.dumps(attestation.to_dict(), indent=2))
        
        verification = prover.verify_proof(attestation)
        print("\nVerification Result:")
        print(json.dumps(verification, indent=2))

if __name__ == "__main__":
    main()