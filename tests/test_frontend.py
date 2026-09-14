"""Browser tests of relay.js and connect.html with Playwright (plan section 8, frontend)."""

from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import threading
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

pw = pytest.importorskip("playwright.sync_api")

WWW = Path(__file__).resolve().parents[1] / "custom_components" / "cloudflare_access_relay" / "www"
ORIGIN = "https://ha.test"
CHROMIUM = os.environ.get("RELAY_TEST_CHROMIUM") or (
    "/opt/pw-browsers/chromium" if Path("/opt/pw-browsers/chromium").exists() else None
)

INDEX_HTML = """<!doctype html><html><body>
<home-assistant></home-assistant>
<script>
  class HomeAssistantStub extends HTMLElement {}
  customElements.define("home-assistant", HomeAssistantStub);
  const el = document.querySelector("home-assistant");
  window.__calls = [];
  el.hass = {
    connection: {},
    callApi: async (method, path) => {
      window.__calls.push([method, path]);
      return JSON.parse(document.body.dataset.session);
    },
  };
</script>
<script src="/cloudflare_access_relay/static/relay.js?v=test"></script>
</body></html>"""


def in_browser(scenario: Callable[[Any], None], timeout: float = 120) -> None:
    """Run `scenario(page)` on a worker thread.

    The Home Assistant pytest plugin drives an asyncio loop on the main thread;
    Playwright's sync API needs a thread without one.
    """
    outcome: dict[str, BaseException] = {}

    def run() -> None:
        try:
            with pw.sync_playwright() as p:
                kwargs: dict[str, Any] = {"headless": True}
                if CHROMIUM:
                    kwargs["executable_path"] = CHROMIUM
                browser = p.chromium.launch(**kwargs)
                try:
                    ctx = browser.new_context()
                    ctx.add_init_script("try{localStorage.clear()}catch(e){}")
                    scenario(ctx.new_page())
                finally:
                    browser.close()
        except BaseException as err:
            outcome["exc"] = err

    worker = threading.Thread(target=run, name="playwright", daemon=True)
    worker.start()
    worker.join(timeout)
    assert not worker.is_alive(), "browser scenario timed out"
    if "exc" in outcome:
        raise outcome["exc"]


def _serve(page: Any, session: dict[str, Any], *, in_app: bool) -> None:
    """Route every request of the fake origin from memory."""
    state = {"session": session}

    def handler(route: Any, request: Any) -> None:
        url = request.url
        path = url[len(ORIGIN) :].split("?")[0]
        if path == "/":
            html = INDEX_HTML.replace(
                "<body>",
                f"<body data-session='{json.dumps(state['session'])}'>",
            )
            if in_app:
                html = html.replace(
                    "<script>", "<script>window.externalApp = {};</script><script>", 1
                )
            route.fulfill(status=200, content_type="text/html", body=html)
        elif path == "/cloudflare_access_relay/static/relay.js":
            route.fulfill(
                status=200, content_type="text/javascript", body=(WWW / "relay.js").read_text()
            )
        elif path == "/cloudflare_access_relay/connect":
            route.fulfill(status=200, content_type="text/html", body="<title>connect stub</title>")
        else:
            route.fulfill(status=404, body="nope")

    page.route(f"{ORIGIN}/**", handler)


def _session(exp: int | None, **over: Any) -> dict[str, Any]:
    base = {
        "exp": exp,
        "renew": exp is not None and exp - 1_800_000_000 < 3 * 86400,
        "cloudflare": True,
        "host_match": True,
        "renew_days": 3,
        "check_interval_min": 60,
        "connect_url": "/cloudflare_access_relay/connect",
    }
    base.update(over)
    return base


NOW = 1_800_000_000  # the stub server computes renew itself; relay.js trusts the flag


def test_renewal_banner_when_two_days_left() -> None:
    def scenario(page: Any) -> None:
        _serve(page, _session(NOW + 2 * 86400), in_app=True)
        page.goto(f"{ORIGIN}/")
        page.wait_for_selector("#cloudflare-access-relay-banner", timeout=10000)
        assert page.url == f"{ORIGIN}/"
        banner = page.locator("#cloudflare-access-relay-banner")
        assert "expires" in banner.inner_text()
        assert banner.locator("a").get_attribute("href") == "/cloudflare_access_relay/connect"
        calls = page.evaluate("window.__calls")
        assert calls == [["GET", "cloudflare_access_relay/session?app=1"]]
        banner.locator("button", has_text="Later").click()
        page.wait_for_selector("#cloudflare-access-relay-banner", state="detached")

    in_browser(scenario)


def test_no_banner_with_ten_days_left() -> None:
    def scenario(page: Any) -> None:
        _serve(page, _session(NOW + 10 * 86400), in_app=True)
        page.goto(f"{ORIGIN}/")
        page.wait_for_function("window.__calls && window.__calls.length > 0")
        page.wait_for_timeout(500)
        assert page.locator("#cloudflare-access-relay-banner").count() == 0
        assert page.url == f"{ORIGIN}/"

    in_browser(scenario)


def test_null_session_in_app_navigates_to_connect() -> None:
    def scenario(page: Any) -> None:
        _serve(page, _session(None), in_app=True)
        page.goto(f"{ORIGIN}/")
        page.wait_for_url(f"{ORIGIN}/cloudflare_access_relay/connect", timeout=10000)

    in_browser(scenario)


def test_null_session_in_browser_does_nothing() -> None:
    def scenario(page: Any) -> None:
        _serve(page, _session(None), in_app=False)
        page.goto(f"{ORIGIN}/")
        page.wait_for_function("window.__calls && window.__calls.length > 0")
        page.wait_for_timeout(500)
        assert page.url == f"{ORIGIN}/"
        assert page.locator("#cloudflare-access-relay-banner").count() == 0
        assert page.evaluate("window.__calls") == [["GET", "cloudflare_access_relay/session?app=0"]]

    in_browser(scenario)


def test_not_via_cloudflare_does_nothing() -> None:
    def scenario(page: Any) -> None:
        _serve(page, _session(None, cloudflare=False), in_app=True)
        page.goto(f"{ORIGIN}/")
        page.wait_for_function("window.__calls && window.__calls.length > 0")
        page.wait_for_timeout(500)
        assert page.url == f"{ORIGIN}/"
        assert page.locator("#cloudflare-access-relay-banner").count() == 0

    in_browser(scenario)


# ---------------------------------------------------------------- connect page


def _serve_connect(
    page: Any, *, status_ok_after: int, callback_status: int = 200
) -> dict[str, Any]:
    seen: dict[str, Any] = {
        "status_calls": 0,
        "flow_posts": 0,
        "auth_headers": set(),
        "callback_hits": 0,
    }

    def handler(route: Any, request: Any) -> None:
        path = request.url[len(ORIGIN) :].split("?")[0]
        auth = request.headers.get("authorization")
        if path == "/cloudflare_access_relay/connect":
            html = (WWW / "connect.html").read_text()
            html = html.replace(
                "<script>",
                "<script>window.externalApp = {getExternalAuth: (p) => { const cb = JSON.parse(p).callback;"
                " setTimeout(() => window[cb](true, {access_token: 'app-token', expires_in: 1800}), 20); }};</script><script>",
                1,
            )
            route.fulfill(status=200, content_type="text/html", body=html)
        elif path == "/api/cloudflare_access_relay/flow" and request.method == "POST":
            seen["flow_posts"] += 1
            seen["auth_headers"].add(auth)
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(
                    {
                        "flow": "F" * 43,
                        "callback": "/cloudflare_access_relay/callback?flow=" + "F" * 43,
                    }
                ),
            )
        elif path == "/api/cloudflare_access_relay/status":
            seen["status_calls"] += 1
            seen["auth_headers"].add(auth)
            if seen["status_calls"] >= status_ok_after:
                route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps({"ok": True, "exp": NOW + 86400}),
                )
            else:
                route.fulfill(
                    status=200, content_type="application/json", body=json.dumps({"ok": False})
                )
        elif path == "/cloudflare_access_relay/callback":
            seen["callback_hits"] += 1
            route.fulfill(
                status=callback_status,
                content_type="text/html",
                body="<title>callback stub</title>",
            )
        elif path == "/":
            route.fulfill(status=200, content_type="text/html", body="<title>home</title>")
        else:
            route.fulfill(status=404, body="nope")

    page.route(f"{ORIGIN}/**", handler)
    return seen


def test_connect_page_uses_app_bridge_and_completes() -> None:
    def scenario(page: Any) -> None:
        seen = _serve_connect(page, status_ok_after=2)
        page.goto(f"{ORIGIN}/cloudflare_access_relay/connect")
        page.wait_for_selector("button:has-text('Sign in with Cloudflare')", timeout=10000)
        assert seen["flow_posts"] == 1
        assert seen["auth_headers"] == {"Bearer app-token"}
        assert page.url.endswith("?flow=" + "F" * 43)
        # polling started before the button is pressed and completes on its own
        page.wait_for_url(f"{ORIGIN}/", timeout=15000)
        assert seen["status_calls"] >= 2

    in_browser(scenario)


def test_connect_page_with_flow_from_deep_link_polls_only() -> None:
    def scenario(page: Any) -> None:
        seen = _serve_connect(page, status_ok_after=1)
        page.goto(f"{ORIGIN}/cloudflare_access_relay/connect?flow=" + "F" * 43)
        page.wait_for_url(f"{ORIGIN}/", timeout=15000)
        assert seen["flow_posts"] == 0
        assert seen["status_calls"] == 1

    in_browser(scenario)


def test_connect_button_navigates_to_callback() -> None:
    def scenario(page: Any) -> None:
        seen = _serve_connect(page, status_ok_after=10_000)
        page.goto(f"{ORIGIN}/cloudflare_access_relay/connect")
        page.wait_for_selector("button:has-text('Sign in with Cloudflare')", timeout=10000)
        page.click("button:has-text('Sign in with Cloudflare')")
        page.wait_for_url(
            f"{ORIGIN}/cloudflare_access_relay/callback?flow=" + "F" * 43, timeout=10000
        )
        assert seen["callback_hits"] == 1

    in_browser(scenario)


def test_connect_page_without_token_offers_login() -> None:
    def scenario(page: Any) -> None:
        def handler(route: Any, request: Any) -> None:
            path = request.url[len(ORIGIN) :].split("?")[0]
            if path == "/cloudflare_access_relay/connect":
                route.fulfill(
                    status=200, content_type="text/html", body=(WWW / "connect.html").read_text()
                )
            elif path == "/auth/authorize":
                route.fulfill(
                    status=200, content_type="text/html", body="<title>login stub</title>"
                )
            else:
                route.fulfill(status=404, body="nope")

        page.route(f"{ORIGIN}/**", handler)
        page.goto(f"{ORIGIN}/cloudflare_access_relay/connect")
        page.wait_for_selector("button:has-text('Sign in')", timeout=10000)
        page.click("button:has-text('Sign in')")
        page.wait_for_url(lambda u: u.startswith(f"{ORIGIN}/auth/authorize?"), timeout=10000)
        qs = parse_qs(urlparse(page.url).query)
        assert qs["response_type"] == ["code"]
        assert qs["client_id"] == [f"{ORIGIN}/"]
        assert qs["redirect_uri"] == [f"{ORIGIN}/cloudflare_access_relay/connect"]

    in_browser(scenario)
