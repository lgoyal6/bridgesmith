"""Copy the committed connector artifacts into a small public demo bundle.
The browser reads these immutable inputs and checks their recorded hashes.
No connector is forged, served, or called by the exporter or demo.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


FILES = ("spec.json", "report.json", "certificate.json")
LIMITS = [
    "This is a saved artifact from the public repository, not a new live run.",
    "The page checks file hashes and compares the recorded spec hashes. It does not validate a registry trust anchor.",
    "The public fixture has no external recovery authority or trusted historical-time proof.",
    "Shape certification does not prove that a correctly typed value is semantically correct.",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Export committed Bridgesmith demo evidence")
    parser.add_argument("--output", type=Path, default=Path("docs/demo"))
    parser.add_argument("--source-commit", default=None)
    args = parser.parse_args()

    source = Path("connectors/devpost/v1")
    target = args.output / "source"
    target.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name in FILES:
        source_path = source / name
        target_path = target / name
        shutil.copyfile(source_path, target_path)
        hashes[name] = sha256(source_path)

    spec = json.loads((target / "spec.json").read_text(encoding="utf-8"))
    report = json.loads((target / "report.json").read_text(encoding="utf-8"))
    certificate = json.loads((target / "certificate.json").read_text(encoding="utf-8"))
    commit = args.source_commit or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip()
    operation = spec["operations"][0]
    evidence = {
        "sourceCommit": commit,
        "sourceHashes": hashes,
        "artifact": {
            "app": spec["app"],
            "version": certificate["version"],
            "tier": spec["tier"],
            "auth": spec["auth"]["kind"],
            "specHash": spec["specHash"],
            "certificateSpecHash": certificate["specHash"],
            "reportSpecHash": report["specHash"],
            "issuedAt": certificate["issuedAt"],
            "operation": {
                "id": operation["id"],
                "method": operation["method"],
                "path": operation["pathTemplate"],
                "queryParams": [row["name"] for row in operation["queryParams"]],
                "responseFields": list(operation["responseSchema"]["properties"]),
            },
            "checks": report["checks"],
            "mutationStats": certificate["mutationStats"],
            "certifiedOps": certificate["certifiedOps"],
            "refusedOps": certificate["refusedOps"],
            "uncoveredOps": report["uncoveredOps"],
            "signatureAlgorithm": "Ed25519",
            "publicKeySha256": hashlib.sha256(certificate["publicKey"].encode()).hexdigest(),
            "signatureBytes": len(base64.b64decode(certificate["signature"])),
        },
        "limits": LIMITS,
    }
    (args.output / "evidence.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
