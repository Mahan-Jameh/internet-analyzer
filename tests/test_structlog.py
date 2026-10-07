import json
import logging

from app import logger as applog
from app.diag.results import RetryOutcome, TechnicalStatus as S, TestResult
from app.diag.structlog import format_event, log_result, result_event


def _r():
    return TestResult("tcp.example.com.443", "tcp", status=S.TIMEOUT, target="example.com", resolved_ip="93.184.216.34",
                      address_family="IPv4", protocol="TCP", port=443, duration_ms=3004.4, attempts=2,
                      retry_outcome=RetryOutcome.PERSISTENT_FAILURE, error_code="TIMEOUT", platform_error=10060,
                      interpretation="POSSIBLY_FILTERED", confidence=0.75,
                      summary="a free text sentence that must not be logged", error_message="secret detail")


def test_line_is_key_value_and_has_no_free_text():
    line = format_event(result_event(_r()))
    assert line.startswith("TEST RESULT test_id=tcp.example.com.443 category=tcp")
    for token in ("status=TIMEOUT", "severity=WARNING", "duration_ms=3004", "attempts=2",
                  "retry=persistent_failure", "error_code=TIMEOUT", "os_error=10060", "confidence=0.75"):
        assert token in line
    assert "free text" not in line and "secret" not in line


def test_json_handler_writes_event(tmp_path):
    handler = applog.JsonLinesHandler(tmp_path / "t.jsonl", encoding="utf-8")
    logger = logging.getLogger("icpa.test_structlog")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        log_result(logger, _r())
        logger.info("plain message")
    finally:
        logger.removeHandler(handler)
        handler.close()
    rows = [json.loads(x) for x in (tmp_path / "t.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["level"] == "WARNING" and rows[0]["event"]["error_code"] == "TIMEOUT"
    assert "event" not in rows[1] and rows[1]["message"] == "plain message"


def test_log_result_never_raises():
    class Broken:
        test_id = "x"
    log_result(logging.getLogger("icpa.x"), Broken())      # must not raise
