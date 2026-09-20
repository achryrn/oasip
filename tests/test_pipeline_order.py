import pytest


def test_module_aliases():
    from oasip.pipeline import parse_modules

    assert parse_modules(["all"]) == ["dns", "ct", "code", "identity", "breach",
                                      "fingerprint", "correlate", "risk"]
    assert "fingerprint" in parse_modules(["infra"])
    assert parse_modules(["dns", "dns", "bogus"]) == ["dns"]


@pytest.mark.asyncio
async def test_authorization_gate(tmp_env):
    from oasip.pipeline import AuthorizationError, run_scan

    tmp_env.accept_risk = False
    with pytest.raises(AuthorizationError):
        await run_scan("example.com", modules=["dns"], cfg=tmp_env)
