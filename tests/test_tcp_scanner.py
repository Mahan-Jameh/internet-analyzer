import errno
import socket

from app.core.tcp_scanner import TCPScanner, classify_connect_result


def test_classification_covers_posix_and_windows_codes():
    assert classify_connect_result(0) == "open"
    assert classify_connect_result(errno.ECONNREFUSED) == "closed"
    assert classify_connect_result(10061) == "closed"
    assert classify_connect_result(errno.ECONNRESET) == "reset"
    assert classify_connect_result(10054) == "reset"
    assert classify_connect_result(errno.ETIMEDOUT) == "timeout"
    assert classify_connect_result(10060) == "timeout"
    assert classify_connect_result(errno.ENETUNREACH) == "unreachable"


def test_ports_outside_allow_list_are_dropped():
    scanner = TCPScanner(ports=[443, 99999, 80, 31337])
    assert scanner.ports == [443, 80]


def test_open_and_closed_port_on_localhost():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port = listener.getsockname()[1]

    spare = socket.socket()
    spare.bind(("127.0.0.1", 0))
    closed_port = spare.getsockname()[1]
    spare.close()                       # nothing listens here any more

    scanner = TCPScanner(target_host="127.0.0.1")
    try:
        assert scanner.probe_port(open_port).state == "open"
        assert scanner.probe_port(closed_port).state == "closed"
    finally:
        listener.close()
