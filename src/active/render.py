from __future__ import annotations
import re, urllib.parse

class Config:
    def _spa(self) -> tuple[str, ...]:
        return (
            "__NEXT_DATA__",
            'id="__next"',
            "id='__next'",
            'id="root"',
            "id='root'",
            '<div id="app"',
        )

class Renderer:
    def __init__(self) -> None:
        self.cfg = Config()

    def _render(self, url: str, timeout: float = 20.0) -> str | None:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
                    page.wait_for_timeout(2500)
                    return page.content()
                finally:
                    browser.close()
        except Exception:
            return None

    def _check(self, url: str, body: str, timeout: float = 20.0) -> str:
        if not any(marker in body for marker in self.cfg._spa()):
            return body
        rendered = self._render(url, timeout)
        if rendered and len(rendered) > len(body) // 2:
            return rendered
        return body

    def _routes(self, body: str, base: str) -> list[str]:
        parsed_base = urllib.parse.urlparse(base)
        routes: set[str] = set()
        for href in re.findall(r'href="([^"]+)"', body):
            if href.startswith("http"):
                p = urllib.parse.urlparse(href)
                if p.netloc and p.netloc != parsed_base.netloc:
                    continue
                path = p.path
            else:
                path = href.split("?")[0].split("#")[0]
            if path and path.startswith("/") and not path.startswith("/_next"):
                routes.add(path)
        return sorted(routes)

_renderer = Renderer()

def _render(url: str, timeout: float = 20.0) -> str | None:
    return _renderer._render(url, timeout)

def _check(url: str, body: str, timeout: float = 20.0) -> str:
    return _renderer._check(url, body, timeout)

def _routes(body: str, base: str) -> list[str]:
    return _renderer._routes(body, base)

render_if_spa = _check
discover_routes = _routes
