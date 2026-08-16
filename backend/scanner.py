"""
Malware / threat scanning abstraction.

    File  ->  Scanner  ->  ScanResult(status, detection_name, detail, engine)

Two engines behind one interface:

  * "demo"   : the default. Detects the industry-standard **EICAR** anti-malware
               test file and applies conservative structural heuristics
               (executable magic bytes, script shebangs). It uses NO external
               dependencies so the project runs anywhere. It is a *teaching /
               demonstration* engine, NOT production antivirus — extension or
               structure checks are explicitly not treated as real detection.

  * "clamav" : a real signature engine. If SCANNER_MODE=clamav and the `clamd`
               client + ClamAV daemon are available, files are scanned by
               ClamAV. Any connection/scan failure returns SCAN_ERROR (which the
               caller treats as "not clean"), never a false CLEAN.

Honest limitation: signature-based scanning only detects *known* threats. A
clean result means "no known signature matched", not "guaranteed safe".
"""

from models import SCAN_CLEAN, SCAN_SUSPICIOUS, SCAN_MALICIOUS, SCAN_ERROR

# The official EICAR test string (harmless; used worldwide to test AV wiring).
# Split so this source file itself is never flagged by a real scanner.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" + "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()

# Structural signals used by the demo heuristics (not "real" AV detection).
_EXECUTABLE_MAGIC = [
    (b"MZ", "Win32 executable (PE/MZ header)"),
    (b"\x7fELF", "Linux executable (ELF header)"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class binary"),
]
_SCRIPT_MARKERS = [
    (b"#!/bin/sh", "Shell script shebang"),
    (b"#!/bin/bash", "Shell script shebang"),
    (b"powershell", "Embedded PowerShell"),
    (b"cmd.exe", "Embedded Windows command"),
]


class ScanResult:
    def __init__(self, status, detection_name=None, detail="", engine="demo"):
        self.status = status
        self.detection_name = detection_name
        self.detail = detail
        self.engine = engine

    def as_tuple(self):
        return self.status, self.detection_name, self.detail, self.engine


def scan_file(path, config):
    """Scan a file on disk and return a ScanResult. Never raises to the caller."""
    mode = (config.get("SCANNER_MODE") or "demo").lower()
    try:
        if mode == "clamav":
            return _scan_clamav(path, config)
        return _scan_demo(path)
    except Exception as exc:  # pragma: no cover - defensive; failures are not "clean"
        return ScanResult(SCAN_ERROR, detail=f"scanner error: {type(exc).__name__}", engine=mode)


# --------------------------------------------------------------------------- #
# Demo engine
# --------------------------------------------------------------------------- #
def _scan_demo(path):
    with open(path, "rb") as f:
        data = f.read()

    # 1) EICAR — the standard, safe way to prove detection works end-to-end.
    if EICAR in data:
        return ScanResult(SCAN_MALICIOUS, "EICAR-Test-Signature",
                          "EICAR standard anti-malware test file detected", "demo")

    head = data[:4096]
    lower = head.lower()

    # 2) Executable binaries uploaded as "documents" are treated as malicious.
    for magic, name in _EXECUTABLE_MAGIC:
        if data[:len(magic)] == magic:
            return ScanResult(SCAN_MALICIOUS, "Heuristic.Executable",
                              f"Executable binary content ({name})", "demo")

    # 3) Embedded scripts / command markers -> suspicious (needs admin review).
    for marker, name in _SCRIPT_MARKERS:
        if marker in lower:
            return ScanResult(SCAN_SUSPICIOUS, "Heuristic.Script",
                              f"Suspicious content: {name}", "demo")

    return ScanResult(SCAN_CLEAN, None, "No known signature matched (demo engine)", "demo")


# --------------------------------------------------------------------------- #
# ClamAV engine (optional, real signatures)
# --------------------------------------------------------------------------- #
def _scan_clamav(path, config):
    try:
        import clamd
    except ImportError:
        return ScanResult(SCAN_ERROR, detail="clamd client not installed", engine="clamav")

    try:
        if config.get("CLAMAV_SOCKET"):
            cd = clamd.ClamdUnixSocket(config["CLAMAV_SOCKET"])
        else:
            cd = clamd.ClamdNetworkSocket(config.get("CLAMAV_HOST", "127.0.0.1"),
                                          int(config.get("CLAMAV_PORT", 3310)),
                                          timeout=int(config.get("SCAN_TIMEOUT_SECONDS", 30)))
        result = cd.scan(path)  # {path: ("FOUND"/"OK", signature)}
    except Exception as exc:
        return ScanResult(SCAN_ERROR, detail=f"ClamAV unreachable: {type(exc).__name__}",
                          engine="clamav")

    verdict = next(iter(result.values()), ("ERROR", None))
    state, signature = verdict[0], (verdict[1] if len(verdict) > 1 else None)
    if state == "OK":
        return ScanResult(SCAN_CLEAN, None, "Clean (ClamAV)", "clamav")
    if state == "FOUND":
        return ScanResult(SCAN_MALICIOUS, signature or "ClamAV.Signature",
                          f"ClamAV signature match: {signature}", "clamav")
    return ScanResult(SCAN_ERROR, detail="ClamAV returned an unknown state", engine="clamav")
