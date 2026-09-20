from oasip.services.wappalyzer import fingerprint


def test_nginx_server_header():
    techs = fingerprint({"server": "nginx/1.18.0"}, "<html></html>")
    nginx = next(t for t in techs if t["name"] == "Nginx")
    assert nginx["version"] == "1.18.0"


def test_cloudflare_cf_ray():
    techs = fingerprint({"server": "cloudflare", "cf-ray": "abc"}, "<html></html>")
    assert any(t["name"] == "Cloudflare" for t in techs)


def test_wordpress_body():
    techs = fingerprint({}, '<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>')
    assert any(t["name"] == "WordPress" for t in techs)


def test_aspnet_headers():
    techs = fingerprint({"x-powered-by": "ASP.NET", "x-aspnet-version": "4.0.30319"}, "<html></html>")
    assert any(t["name"] == "ASP.NET" for t in techs)


def test_empty():
    assert fingerprint({}, "<html></html>") == []
