# pyrad2 Project Scan - Issues Found

Scan date: 2026-02-22

## Critical Issues

### 1. Runtime Bug: Typo in `examples/auth.py:34`
`logger.inferroro()` is not a valid loguru method. Will raise `AttributeError` at runtime.
**Fix:** Change to `logger.error()`.

### 2. Missing ABC Inheritance in `pyrad2/radsec/server.py:29`
`RadSecServer` uses `@abstractmethod` decorators but does not inherit from `ABC`.
Python won't enforce the abstract contract at instantiation time.
**Fix:** Add `ABC` to the class bases: `class RadSecServer(ABC):` and import `ABC` from `abc`.

### 3. Duplicate `CreateID()` with Different Behavior in `pyrad2/packet.py`
- `Packet.CreateID()` (line 383): generates a **random** ID (0-255)
- Module-level `CreateID()` (line 1000): uses a **sequential** counter

These have different semantics, creating ambiguity.
**Fix:** Consolidate to a single implementation and deprecate the other.

## Security Issues

### 4. Weak/Broken TLS Ciphers in `pyrad2/radsec/server.py:46`
```
ALLOWED_CIPHERS = "DES-CBC3-SHA:RC4-SHA:AES128-SHA"
```
- RC4 is broken (RFC 7465)
- 3DES is deprecated (Sweet32 / CVE-2016-2183)
- AES128-SHA uses CBC without AEAD

**Fix:** Use modern ciphers: `ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384`

### 5. Default `verify_mode=ssl.CERT_NONE` in `pyrad2/radsec/server.py:58`
RadSec (RFC 6614) relies on mutual TLS. Defaulting to `CERT_NONE` undermines security.
**Fix:** Default to `ssl.CERT_REQUIRED`.

## Medium Priority

### 6. Double Slash in Path: `pyrad2/radsec/client.py:33`
`certfile_server: str = "certs//ca/ca.cert.pem"` should be `"certs/ca/ca.cert.pem"`.

### 7. Docs Dependencies in Main Project Dependencies
`pyproject.toml` includes `mkdocs-material` and `mkdocstrings` in `[project.dependencies]`.
These should only be in the `[dependency-groups] docs` group.

### 8. Test Type Mismatches: `tests/test_client.py`
Tests pass `secret="secret"` (str) where `Client` expects `secret: bytes`.

### 9. Mypy Type Errors in `pyrad2/client.py`
2 type errors related to `Union[int | HasFileno]` in Windows selector code.

### 10. Ruff Formatting Violations
3 files need reformatting: `pyrad2/client.py`, `pyrad2/proxy.py`, `pyrad2/server.py`.

## Low Priority

### 11. Docstring Typos in `pyrad2/radsec/server.py`
- Line 64: "Deafaults" -> "Defaults"
- Line 70: "certfificate" -> "certificate"

### 12. Incomplete Feature: Status-Server Handling
`pyrad2/packet.py:201`: `# TODO: Handle Status-Server response correctly.`

### 13. Low Test Coverage on New Modules
RadSec and async modules have 0-59% coverage vs 95-100% for core modules.
