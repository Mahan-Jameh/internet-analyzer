from app.core.dns_test import DNSTester, is_suspicious_answer
from app.models import Status


def test_private_and_loopback_answers_are_suspicious():
    for ip in ("10.10.34.34", "192.168.1.1", "127.0.0.1", "0.0.0.0", "169.254.1.1"):
        assert is_suspicious_answer(ip)
    for ip in ("1.1.1.1", "142.250.1.1", "not-an-ip"):
        assert not is_suspicious_answer(ip)


def _answers(**per_domain):
    return {"cloudflare.com": per_domain.get("cf", []), "google.com": per_domain.get("g", []),
            "wikipedia.org": per_domain.get("w", [])}


def test_block_page_address_fails_even_if_one_resolver_returned_it():
    data = {
        "System": _answers(cf=["10.10.34.34"]),
        "Google": _answers(cf=["104.16.0.1"]),
    }
    result = DNSTester()._compare_answers(data)
    assert result.status == Status.FAILED


def test_cdn_variance_alone_is_not_flagged():
    # Every resolver differs a bit, but each overlaps with at least one other.
    data = {
        "Google": _answers(g=["1.1.1.1", "1.1.1.2"]),
        "Cloudflare": _answers(g=["1.1.1.2", "1.1.1.3"]),
        "Quad9": _answers(g=["1.1.1.3", "1.1.1.4"]),
        "System": _answers(g=["1.1.1.4", "1.1.1.1"]),
    }
    assert DNSTester()._compare_answers(data).status == Status.OK


def test_resolver_sharing_nothing_with_the_rest_is_a_warning():
    data = {
        "Google": _answers(g=["142.250.1.1"]),
        "Cloudflare": _answers(g=["142.250.1.1", "142.250.1.2"]),
        "Quad9": _answers(g=["142.250.1.2"]),
        "System": _answers(g=["93.184.216.34"]),
    }
    result = DNSTester()._compare_answers(data)
    assert result.status == Status.WARNING
    assert result.details["outlier_resolvers"]["google.com"] == ["System"]
