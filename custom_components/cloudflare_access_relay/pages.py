"""Plain HTML pages served by the relay (no framework, no external assets)."""

from __future__ import annotations

from html import escape

from .const import URL_CONNECT

_STYLE = """
body{font-family:system-ui,-apple-system,Roboto,sans-serif;background:#f4f6f8;color:#1f2933;
margin:0;padding:24px 16px;display:flex;justify-content:center}
main{max-width:520px;width:100%;background:#fff;border-radius:12px;padding:24px;
box-shadow:0 1px 3px rgba(0,0,0,.12)}
h1{font-size:1.25rem;margin:0 0 12px}p{line-height:1.5}code{background:#eef1f4;padding:1px 4px;border-radius:4px}
a.btn{display:inline-block;margin:8px 8px 0 0;padding:10px 16px;border-radius:8px;text-decoration:none;
background:#03a9f4;color:#fff;font-weight:600}a.btn.secondary{background:#e0e4e8;color:#1f2933}
.err h1{color:#b00020}
@media (prefers-color-scheme:dark){body{background:#111417;color:#e6e9ec}main{background:#1c2126}
code{background:#2a3138}a.btn.secondary{background:#2a3138;color:#e6e9ec}}
"""


def _page(title: str, body: str, *, error: bool = False) -> str:
    cls = ' class="err"' if error else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main{cls}><h1>{escape(title)}</h1>{body}</main></body></html>"
    )


def callback_success(flow_id: str) -> str:
    """Page shown in the browser once the Access token has been captured."""
    connect = f"{URL_CONNECT}?flow={escape(flow_id, quote=True)}"
    deep_link = f"homeassistant://navigate{connect}"
    body = (
        "<p>Cloudflare Access verified you. The Home Assistant app can now "
        "pick up the session.</p>"
        "<p>If the app is still showing its connect page, switch back to it: "
        "it completes on its own. Otherwise open the app from here.</p>"
        f'<a class="btn" href="{deep_link}">Open in the Home Assistant app</a>'
        f'<a class="btn secondary" href="{connect}">Continue here</a>'
    )
    return _page("Connected", body)


def callback_error(status_title: str, reason: str, hint: str) -> str:
    """Readable failure page; never contains the token."""
    body = (
        f"<p>{escape(reason)}</p><p>{hint}</p>"
        f'<a class="btn secondary" href="{URL_CONNECT}">Start again</a>'
    )
    return _page(status_title, body, error=True)


HINT_NO_HEADER = (
    "No <code>Cf-Access-Jwt-Assertion</code> header reached Home Assistant on this "
    "path. The callback path must be covered by the relay's gate application and "
    "must not be bypassed. The Access applications may have been edited outside "
    "the integration; reload the integration (Settings → Devices &amp; services → "
    "Cloudflare Access Relay → Reload) to re-provision them."
)
HINT_UNKNOWN_FLOW = (
    "The connect attempt is unknown or older than ten minutes. Start again from "
    "the app; each attempt is valid for ten minutes and can be used once."
)
HINT_REJECTED = (
    "The token Cloudflare sent could not be accepted. If the applications were "
    "changed outside the integration, reload the integration to re-provision them."
)
HINT_IDENTITY = (
    "The identity Cloudflare Access reported does not belong to the Home Assistant "
    "user who started this connect attempt. Sign in to Cloudflare Access with the "
    "account whose identity claim matches your Home Assistant user, or adjust the "
    "identity claim and user match options of the integration."
)
HINT_DISABLED = "The Cloudflare Access relay integration is not loaded for this hostname."
