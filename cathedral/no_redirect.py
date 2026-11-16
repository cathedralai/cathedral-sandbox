"""Refuse HTTP redirects before a keyed request can be sent to another URL."""

from __future__ import annotations

import re
import urllib.parse
import urllib.request


class RedirectRefused(OSError):
    """A response tried to redirect a request carrying a credential."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def _refuse(self, req, response, headers):
        try:
            location = headers.get("Location") or headers.get("URI")
            target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, location))
            if target.scheme not in ("http", "https") or not target.hostname:
                raise ValueError("unsupported redirect target")
            host = target.hostname
            port = target.port
            # Never echo a Location path, query, userinfo, or control character.
            if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
                raise ValueError("unsafe redirect host")
            address = f"{host}:{port}" if port is not None else host
            message = f"redirect refused to {address}"
        except (TypeError, ValueError, UnicodeError):
            message = "redirect refused"
        finally:
            response.close()
        raise RedirectRefused(message)

    def http_error_301(self, req, response, code, message, headers):
        self._refuse(req, response, headers)

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301
