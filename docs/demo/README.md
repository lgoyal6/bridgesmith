# Bridgesmith connector evidence explorer

This static page reads the committed Devpost v1 connector spec, certification
report, and certificate. It checks the copied files against pinned SHA256
values and confirms that the three recorded spec hashes agree.

Regenerate the public bundle from the repository root:

```sh
python3 scripts/export_demo_evidence.py
```

The page does not contact Devpost, certify a new connector, mount a connector,
or validate an independent registry trust root. The saved certificate contains
a public key and signature, but the repository does not publish the external
root and expected keyring head needed for rollback-aware trust verification.
