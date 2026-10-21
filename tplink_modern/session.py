from typing import Any

import httpx

from tplink_modern.exceptions import SessionExpiredError

# The AX12 keeps a single admin session and answers HTTP 200 with these error codes once
# another login has replaced our stok.
EXPIRED_ERROR_CODES = frozenset({"permission denied", "timeout"})

# The web UI's own normalizer destructures all four of these and re-emits one field, in this order.
# Watching only `errorcode` would let a session loss reported under another spelling be read as data.
ERROR_FIELDS = ("errorCode", "error", "error_code", "errorcode")


def error_field(response: dict[str, Any]) -> Any:
    """The router's refusal reason, under whichever of its four spellings it arrived."""
    for name in ERROR_FIELDS:
        value = response.get(name)
        if value not in (None, ""):
            return value
    return None


class RouterSession:
    def __init__(self, host: str, timeout: float = 10.0, verify: bool = True):
        """Normalize the host and build the HTTP client.

        `verify` only matters for an `https://` host; the router serves plain HTTP on the LAN.
        It defaults to on so a certificate problem is an error rather than something silently
        accepted -- pass verify=False deliberately, for a device with a self-signed certificate.
        """
        host_clean = host.rstrip("/")
        if not host_clean.startswith(("http://", "https://")):
            self.base_url = f"http://{host_clean}"
        else:
            self.base_url = host_clean

        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=True,
            verify=verify,
        )
        self.stok: str | None = None
        self.generation = 0

    async def post(self, path: str, data: dict[str, Any], use_login_stok: bool = False) -> dict[str, Any]:
        """Send a POST request to the router's Luci CGI endpoint.
        
        Args:
            path: The endpoint path (e.g. 'admin/status?form=all' or 'login?form=auth')
            data: Form-urlencoded request body dict.
            use_login_stok: Force use of '/login' instead of session token (for login phase).
        """
        stok_val = "/login" if (self.stok is None or use_login_stok) else self.stok
        
        # Clean path and format URL
        clean_path = path.lstrip("/")

        if self.stok is None or use_login_stok:
            _, separator, query = clean_path.partition("?")

            if separator:
                url = f"/cgi-bin/luci/;stok=/login?{query}"
            else:
                url = "/cgi-bin/luci/;stok=/login"
        else:
            url = f"/cgi-bin/luci/;stok={self.stok}/{clean_path}"
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{self.base_url}/webpages/index.html#/login",
        }
        
        response = await self.client.post(url, data=data, headers=headers)
        
        # Check HTTP authentication failure
        if response.status_code in (401, 403):
            raise SessionExpiredError("Session expired or permission denied")
            
        response.raise_for_status()
        res_json = response.json()

        # Check for TP-Link specific session expiration indicators
        err_code = error_field(res_json)
        if err_code in EXPIRED_ERROR_CODES:
            raise SessionExpiredError(f"Session no longer accepted by router: {err_code}")

        return res_json

    async def close(self):
        await self.client.aclose()
