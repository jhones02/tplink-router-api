import asyncio
from typing import Any

import httpx

from tplink_modern.auth import Authenticator
from tplink_modern.exceptions import (
    APIError,
    FeatureUnavailableError,
    RouterError,
    SessionExpiredError,
)
from tplink_modern.models import RouterStatus
from tplink_modern.resources import (
    AccessControlResource,
    ClientsResource,
    FirmwareResource,
    NatResource,
    NetworkResource,
    StatusResource,
    SystemResource,
    VpnResource,
    WakeOnLanResource,
    WifiResource,
)
from tplink_modern.session import RouterSession, error_field


def _checked(path: str, response: dict[str, Any]) -> dict[str, Any]:
    """Raise a typed error unless the router reported success."""
    if response.get("success"):
        return response

    errorcode = error_field(response)
    detail = f"{path} refused by router" + (f": {errorcode}" if errorcode else "")
    if errorcode == "no such callback":
        raise FeatureUnavailableError(detail, errorcode)
    raise APIError(detail, errorcode)


class ArcherAX12:
    def __init__(self, host: str, password: str, timeout: float = 10.0, verify: bool = True):
        """Initialize the Archer AX12 router client.
        
        Args:
            host: The router host IP or domain (e.g. '192.168.0.1' or 'wifi.config').
            password: The administration login password.
            timeout: Seconds for each router request.
            verify: Verify TLS certificates; only relevant for an https:// host.
        """
        self.session = RouterSession(host, timeout=timeout, verify=verify)
        self.password = password
        self._authenticator = Authenticator(self.session)
        self._auth_lock = asyncio.Lock()

        # Expose sub-resources
        self.status = StatusResource(self)
        self.firmware = FirmwareResource(self)
        self.clients = ClientsResource(self)
        self.wifi = WifiResource(self)
        self.network = NetworkResource(self)
        self.system = SystemResource(self)
        self.vpn = VpnResource(self)
        self.access = AccessControlResource(self)
        self.nat = NatResource(self)
        self.wol = WakeOnLanResource(self)


    async def login(self) -> None:
        """Authenticate with the router and verify that the session is active."""
        # 1. Perform login handshake to retrieve stok
        await self._authenticator.login(self.password)
        # 2. Immediately verify login by fetching status
        await self.get_status()

    async def read(self, path: str, form: str, **kwargs) -> dict[str, Any]:
        """Perform a low-level read operation against the router.
        
        This translates to a POST request to path?form=form with operation=read.
        """
        full_path = f"{path}?form={form}"
        data = {"operation": "read", **kwargs}
        return await self._request(full_path, data)

    async def write(self, path: str, form: str, **kwargs) -> dict[str, Any]:
        """Perform a low-level write operation against the router.
        
        This translates to a POST request to path?form=form with operation=write.
        """
        full_path = f"{path}?form={form}"
        data = {"operation": "write", **kwargs}
        return await self._request(full_path, data)

    async def api(self, path: str, form: str, operation: str, **kwargs) -> dict[str, Any]:
        """Perform a low-level generic operation against the router."""
        full_path = f"{path}?form={form}"
        data = {"operation": operation, **kwargs}
        return await self._request(full_path, data)

    async def _request(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Wrapper for posting requests that handles transparent re-authentication on session expiration."""
        generation = self.session.generation
        try:
            response = await self._authenticator.request(path, data)
        except SessionExpiredError:
            # Re-auth one at a time: this firmware keeps a single admin session, so parallel
            # logins invalidate each other's stok and every caller would end up failing.
            # Whoever finds the generation already advanced just retries on the token
            # somebody else fetched.
            async with self._auth_lock:
                if self.session.generation == generation:
                    await self._authenticator.login(self.password)
            response = await self._authenticator.request(path, data)
        return _checked(path, response)

    async def get_status(self) -> RouterStatus:
        """Fetch router status information.

        This also acts as a verification endpoint for the session.
        """
        resp = await self._request("admin/status?form=all", {"operation": "read"})

        try:
            return RouterStatus.from_raw(resp.get("data", {}))
        except Exception as e:
            raise APIError(f"Failed to parse router status data: {e}") from e

    async def keep_alive(self) -> bool:
        """Ping the router to keep the session alive.
        
        Returns:
            True if the session is alive (or was successfully re-authenticated), False otherwise.
        """
        try:
            # Query a cheap status endpoint
            await self._request("admin/status?form=internet", {"operation": "read"})
            return True
        except (RouterError, httpx.HTTPError):
            return False

    async def logout(self) -> None:
        """Cleanly terminate the session on the router."""
        if self.session.stok:
            try:
                # Post to logout endpoint
                await self._authenticator.request("admin/system?form=logout", {})
            except (RouterError, httpx.HTTPError):
                # A router that is already gone should not turn teardown into an error;
                # the token is cleared in `finally` either way.
                pass
            finally:
                self.session.stok = None

    async def close(self) -> None:
        """Log out and close the underlying HTTP client session."""
        try:
            await self.logout()
        finally:
            await self.session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
