"""
neterrors.py
============
Turns raw exceptions and OS error numbers into :class:`NormalizedError`.

Windows reports socket failures as ``WSAExxxx`` numbers (10060 = timed out)
while POSIX uses small ``errno`` values (110 = timed out). Both are mapped
here, so no other module ever compares a raw number.
"""

from __future__ import annotations

import errno
import socket
import ssl
from dataclasses import dataclass

from app.diag.results import TechnicalStatus

# code name -> (status, recoverable, human text)
_T = TechnicalStatus
_CODES: dict[str, tuple[TechnicalStatus, bool, str]] = {
    "TIMEOUT": (_T.TIMEOUT, True, "no answer within the time limit"),
    "CONNECTION_REFUSED": (_T.CLOSED, False, "connection actively refused"),
    "CONNECTION_RESET": (_T.RESET, True, "connection reset by peer or middlebox"),
    "CONNECTION_ABORTED": (_T.RESET, True, "connection aborted"),
    "NETWORK_UNREACHABLE": (_T.UNREACHABLE, False, "network unreachable"),
    "HOST_UNREACHABLE": (_T.UNREACHABLE, False, "host unreachable"),
    "NETWORK_DOWN": (_T.UNREACHABLE, False, "network is down"),
    "PERMISSION_DENIED": (_T.ERROR, False, "operation not permitted locally"),
    "ADDRESS_NOT_AVAILABLE": (_T.ERROR, False, "no usable local address for this family"),
    "ADDRESS_FAMILY_UNSUPPORTED": (_T.UNREACHABLE, False, "address family not supported / not configured"),
    "NO_BUFFER_SPACE": (_T.ERROR, True, "local resource exhaustion"),
    "MESSAGE_TOO_LONG": (_T.ERROR, False, "datagram larger than the path allows"),
    "HOST_NOT_FOUND": (_T.DNS_FAILED, False, "name does not exist"),
    "DNS_TEMPORARY_FAILURE": (_T.DNS_FAILED, True, "temporary DNS failure"),
    "DNS_NO_RECOVERY": (_T.DNS_FAILED, False, "non-recoverable DNS failure"),
    "DNS_NO_DATA": (_T.DNS_FAILED, False, "name exists but has no record of this type"),
    "WOULD_BLOCK": (_T.TIMEOUT, True, "operation did not complete in time"),
}

# OS number -> code name. POSIX values come from ``errno`` so the table is
# correct on whichever platform this runs; WSA numbers are listed literally.
_OS_NUMBERS: dict[int, str] = {
    10060: "TIMEOUT", 10061: "CONNECTION_REFUSED", 10054: "CONNECTION_RESET",
    10053: "CONNECTION_ABORTED", 10051: "NETWORK_UNREACHABLE", 10065: "HOST_UNREACHABLE",
    10050: "NETWORK_DOWN", 10013: "PERMISSION_DENIED", 10049: "ADDRESS_NOT_AVAILABLE",
    10047: "ADDRESS_FAMILY_UNSUPPORTED", 10055: "NO_BUFFER_SPACE", 10040: "MESSAGE_TOO_LONG",
    10035: "WOULD_BLOCK", 10036: "WOULD_BLOCK",
    11001: "HOST_NOT_FOUND", 11002: "DNS_TEMPORARY_FAILURE",
    11003: "DNS_NO_RECOVERY", 11004: "DNS_NO_DATA",
}
for _name, _code in (
    ("ETIMEDOUT", "TIMEOUT"), ("ECONNREFUSED", "CONNECTION_REFUSED"),
    ("ECONNRESET", "CONNECTION_RESET"), ("ECONNABORTED", "CONNECTION_ABORTED"),
    ("ENETUNREACH", "NETWORK_UNREACHABLE"), ("EHOSTUNREACH", "HOST_UNREACHABLE"),
    ("ENETDOWN", "NETWORK_DOWN"), ("EACCES", "PERMISSION_DENIED"), ("EPERM", "PERMISSION_DENIED"),
    ("EADDRNOTAVAIL", "ADDRESS_NOT_AVAILABLE"), ("EAFNOSUPPORT", "ADDRESS_FAMILY_UNSUPPORTED"),
    ("ENOBUFS", "NO_BUFFER_SPACE"), ("EMSGSIZE", "MESSAGE_TOO_LONG"),
    ("EAGAIN", "WOULD_BLOCK"), ("EWOULDBLOCK", "WOULD_BLOCK"),
):
    _num = getattr(errno, _name, None)
    if _num is not None:
        _OS_NUMBERS.setdefault(_num, _code)

# getaddrinfo() error numbers (POSIX EAI_*; Windows reuses the 1100x WSA values above)
_GAI: dict[int, str] = {
    getattr(socket, "EAI_NONAME", -2): "HOST_NOT_FOUND",
    getattr(socket, "EAI_AGAIN", -3): "DNS_TEMPORARY_FAILURE",
    getattr(socket, "EAI_FAIL", -4): "DNS_NO_RECOVERY",
    getattr(socket, "EAI_NODATA", -5): "DNS_NO_DATA",
    getattr(socket, "EAI_FAMILY", -6): "ADDRESS_FAMILY_UNSUPPORTED",
}

WSA_NAMES: dict[int, str] = {
    10060: "WSAETIMEDOUT", 10061: "WSAECONNREFUSED", 10054: "WSAECONNRESET",
    10053: "WSAECONNABORTED", 10051: "WSAENETUNREACH", 10065: "WSAEHOSTUNREACH",
    10050: "WSAENETDOWN", 10013: "WSAEACCES", 10049: "WSAEADDRNOTAVAIL",
    10047: "WSAEAFNOSUPPORT", 10055: "WSAENOBUFS", 10040: "WSAEMSGSIZE",
    10035: "WSAEWOULDBLOCK", 11001: "WSAHOST_NOT_FOUND", 11002: "WSATRY_AGAIN",
    11003: "WSANO_RECOVERY", 11004: "WSANO_DATA",
}


@dataclass(frozen=True)
class NormalizedError:
    error_type: str                  # exception class or category, e.g. "ConnectionRefusedError"
    error_code: str                  # stable name, e.g. "CONNECTION_REFUSED"
    error_message: str               # short, user-safe text (no stack trace)
    status: TechnicalStatus          # what this means for the measurement
    platform_error: int | None = None  # raw OS number (errno / WSA)
    platform_name: str | None = None   # e.g. "WSAECONNREFUSED" / "ECONNREFUSED"
    recoverable: bool = False


def _from_code(code_name: str, exc_type: str, message: str, number: int | None) -> NormalizedError:
    status, recoverable, text = _CODES[code_name]
    platform_name = WSA_NAMES.get(number) if number is not None else None
    if platform_name is None and number is not None:
        platform_name = errno.errorcode.get(number)
    return NormalizedError(exc_type, code_name, message or text, status, number, platform_name, recoverable)


def classify_os_error(number: int | None) -> str | None:
    """Return our stable code name for an OS error number, or None."""
    if number is None:
        return None
    return _OS_NUMBERS.get(number)


def normalize_os_error(number: int, message: str = "") -> NormalizedError:
    """Normalize a bare ``connect_ex``-style error number."""
    code = classify_os_error(number)
    if code is None:
        return NormalizedError("OSError", "OS_ERROR", message or f"OS error {number}",
                               TechnicalStatus.ERROR, number, errno.errorcode.get(number), False)
    return _from_code(code, "OSError", message, number)


def normalize_exception(exc: BaseException) -> NormalizedError:
    """
    Normalize any exception raised while probing the network.

    The full traceback is *not* kept here (it belongs in debug logs); only a
    short message is retained so reports stay readable.
    """
    name = type(exc).__name__
    text = str(exc)

    if isinstance(exc, ssl.SSLCertVerificationError):
        return NormalizedError(name, "CERTIFICATE_ERROR", getattr(exc, "verify_message", "") or text,
                               TechnicalStatus.TLS_FAILED, None, None, False)
    if isinstance(exc, ssl.SSLError):
        return NormalizedError(name, "TLS_PROTOCOL_ERROR", text, TechnicalStatus.TLS_FAILED,
                               exc.errno, None, True)
    if isinstance(exc, socket.gaierror):
        num = exc.errno
        code = _GAI.get(num) or _OS_NUMBERS.get(num if num is not None else -99, "HOST_NOT_FOUND")
        return _from_code(code, name, text, num)
    if isinstance(exc, (socket.timeout, TimeoutError)) and getattr(exc, "errno", None) in (None, 0):
        return _from_code("TIMEOUT", name, text or "timed out", None)
    if isinstance(exc, PermissionError):
        return _from_code("PERMISSION_DENIED", name, text, exc.errno)
    if isinstance(exc, OSError):
        code = classify_os_error(exc.errno)
        if code:
            return _from_code(code, name, text, exc.errno)
        return NormalizedError(name, "OS_ERROR", text, TechnicalStatus.ERROR, exc.errno,
                               errno.errorcode.get(exc.errno) if exc.errno else None, False)
    if isinstance(exc, ConnectionRefusedError):  # pragma: no cover - subclass of OSError above
        return _from_code("CONNECTION_REFUSED", name, text, None)

    lowered = name.lower()
    if "timeout" in lowered:
        return _from_code("TIMEOUT", name, text, None)
    if "dns" in lowered and "nxdomain" in lowered:
        return _from_code("HOST_NOT_FOUND", name, text, None)
    return NormalizedError(name, "UNEXPECTED_ERROR", text[:200], TechnicalStatus.ERROR, None, None, False)


def _walk_causes(exc: BaseException, limit: int = 8) -> list[BaseException]:
    """The exception plus everything it wraps (``__cause__``, ``__context__``, args, ``.reason``)."""
    seen: list[BaseException] = []
    stack: list[BaseException] = [exc]
    while stack and len(seen) < limit:
        cur = stack.pop(0)
        if cur in seen:
            continue
        seen.append(cur)
        for nxt in (cur.__cause__, cur.__context__, getattr(cur, "reason", None), *getattr(cur, "args", ())):
            if isinstance(nxt, BaseException):
                stack.append(nxt)
    return seen


def normalize_wrapped_exception(exc: BaseException) -> NormalizedError:
    """
    Normalize an exception raised by ``requests`` / ``httpx`` / ``urllib3`` / ``aioquic``:
    those libraries wrap the real socket or SSL error, which is what carries the meaning.
    """
    chain = _walk_causes(exc)
    for item in chain:                                # most specific first
        if isinstance(item, (ssl.SSLError, socket.gaierror, OSError)) and type(item).__module__ in (
                "ssl", "socket", "builtins"):
            norm = normalize_exception(item)
            if norm.error_code not in ("OS_ERROR",) or item is chain[-1]:
                return NormalizedError(type(exc).__name__, norm.error_code, norm.error_message, norm.status,
                                       norm.platform_error, norm.platform_name, norm.recoverable)
    text = " ".join(str(i) for i in chain).lower()
    name = type(exc).__name__
    if "certificate" in text or "cert_verify" in text:
        return NormalizedError(name, "CERTIFICATE_ERROR", str(exc)[:200], _T.TLS_FAILED)
    if "name or service not known" in text or "getaddrinfo" in text or "nodename nor servname" in text:
        return _from_code("HOST_NOT_FOUND", name, str(exc)[:200], None)
    if "timed out" in text or "timeout" in name.lower():
        return _from_code("TIMEOUT", name, str(exc)[:200], None)
    if "ssl" in text or "tls" in text:
        return NormalizedError(name, "TLS_PROTOCOL_ERROR", str(exc)[:200], _T.TLS_FAILED, None, None, True)
    if "refused" in text:
        return _from_code("CONNECTION_REFUSED", name, str(exc)[:200], None)
    if "reset" in text:
        return _from_code("CONNECTION_RESET", name, str(exc)[:200], None)
    return normalize_exception(exc)
