import hmac
import json
from base64 import b64encode, b64decode
from binascii import hexlify
from hashlib import sha256
from random import randint
from urllib.parse import urlencode

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5, AES
from Crypto.PublicKey.RSA import construct
from Crypto.Util.Padding import pad, unpad

from tplink_modern.exceptions import APIError, AuthenticationError
from tplink_modern.session import RouterSession

SIGNATURE_OFFSET = 53
AES_KEY_LEN = 16


class Authenticator:
    """SHA256 + RSA/AES login handshake used by SG/CE_RED-certified TP-Link firmware."""

    def __init__(self, session: RouterSession, username: str = 'admin') -> None:
        self.session = session
        self.username = username
        self._aes_key = ''
        self._aes_iv = ''
        self._hash = ''
        self._seq = 0
        self._nn = ''
        self._ee = ''
        self._pwdNN = ''
        self._pwdEE = ''

    def _generate_aes_key(self) -> None:
        """Generate random AES key and IV (16 random digits, matching JS behavior)."""
        self._aes_key = ''.join(str(randint(0, 9)) for _ in range(AES_KEY_LEN))
        self._aes_iv = ''.join(str(randint(0, 9)) for _ in range(AES_KEY_LEN))

    def _aes_encrypt(self, data: str) -> str:
        """AES-CBC encrypt with PKCS7 padding."""
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

    def _aes_decrypt(self, data: str) -> str:
        """AES-CBC decrypt with PKCS7 unpadding."""
        cipher = AES.new(self._aes_key.encode(), AES.MODE_CBC, self._aes_iv.encode())
        return unpad(cipher.decrypt(b64decode(data)), AES.block_size).decode()

    @staticmethod
    def _rsa_v15_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        """RSA encrypt with PKCS1 v1.5 padding (used for password encryption)."""
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_v1_5.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    @staticmethod
    def _rsa_oaep_encrypt(data: str, n_hex: str, e_hex: str) -> str:
        """RSA encrypt with PKCS1-OAEP padding (used for login signature)."""
        key = construct((int(n_hex, 16), int(e_hex, 16)))
        cipher = PKCS1_OAEP.new(key)
        result = hexlify(cipher.encrypt(data.encode())).decode()
        key_len = len(n_hex)
        return result.zfill(key_len) if len(result) < key_len else result

    def _get_aes_formatted_key(self) -> str:
        return 'k={}&i={}'.format(self._aes_key, self._aes_iv)

    async def _request_pwd_keys(self) -> None:
        """Get RSA public key for password encryption."""
        response = await self.session.post(
            'login?form=keys', {'operation': 'read'}, use_login_stok=True)
        try:
            self._pwdNN = response['data']['password'][0]
            self._pwdEE = response['data']['password'][1]
        except (KeyError, IndexError, TypeError) as e:
            raise AuthenticationError(f'Failed to get password keys: {e}') from e

    async def _request_auth_keys(self) -> None:
        """Get sequence number and RSA public key for data encryption."""
        response = await self.session.post(
            'login?form=auth', {'operation': 'read'}, use_login_stok=True)
        try:
            self._seq = response['data']['seq']
            self._nn = response['data']['key'][0]
            self._ee = response['data']['key'][1]
        except (KeyError, IndexError, TypeError) as e:
            raise AuthenticationError(f'Failed to get auth keys: {e}') from e

    def _build_login_signature(self, data_len: int) -> str:
        """Build RSA-OAEP encrypted signature for the login request."""
        sign_str = '{}&h={}&s={}'.format(
            self._get_aes_formatted_key(), self._hash, self._seq + data_len)
        sign = ''
        # OAEP overhead (SHA-1, pycryptodome's default hash for PKCS1_OAEP.new())
        # is 2*hLen+2 = 42 bytes, unlike PKCS1v1.5's 11-byte overhead. The fixed
        # SIGNATURE_OFFSET (53, sized for PKCS1v1.5) overflows small auth keys
        # (e.g. 512-bit, max OAEP payload 22 bytes), raising "Plaintext is too
        # long." on every login attempt. Cap at SIGNATURE_OFFSET rather than
        # always using the OAEP-safe max: for keys large enough that 53 never
        # overflowed (e.g. 1024-bit, max payload 86 bytes), this keeps the
        # exact legacy chunking unchanged, in case some firmware's signature
        # parsing is sensitive to the resulting block size/count.
        rsa_byte_len = len(self._nn) // 2
        oaep_step = min(SIGNATURE_OFFSET, rsa_byte_len - 2 * 20 - 2)
        for i in range(0, len(sign_str), oaep_step):
            chunk = sign_str[i:i + oaep_step]
            sign += self._rsa_oaep_encrypt(chunk, self._nn, self._ee)
        return sign

    def _build_request_signature(self, data_len: int) -> str:
        """Build HMAC-SHA256 signature for authenticated (non-login) requests."""
        sign_str = 'h={}&s={}'.format(self._hash, self._seq + data_len)
        aes_key = self._get_aes_formatted_key()
        sign = ''
        for i in range(0, len(sign_str), SIGNATURE_OFFSET):
            chunk = sign_str[i:i + SIGNATURE_OFFSET]
            h = hmac.new(aes_key.encode(), chunk.encode(), sha256)
            sign += h.hexdigest()
        return sign

    async def request(self, path: str, data: dict) -> dict:
        """Send an AES-encrypted, HMAC-signed request using the established session key.

        Every request past login must be encrypted the same way login's final step was --
        this firmware answers an unencrypted authenticated request with a plain 403, which
        looks identical to an expired session.
        """
        encrypted_data = self._aes_encrypt(urlencode(data))
        # REPLACE_HASH: this request's signature is keyed off the hash of its own
        # encrypted payload, not the previous one.
        self._hash = sha256(encrypted_data.encode()).hexdigest()
        sign = self._build_request_signature(len(encrypted_data))

        response = await self.session.post(path, {'sign': sign, 'data': encrypted_data})

        try:
            return json.loads(self._aes_decrypt(response['data']))
        except Exception as e:
            raise APIError(f'Cannot decrypt response for {path}: {e}') from e

    async def login(self, password: str) -> None:
        """Run the login handshake and store the resulting session token."""
        await self._request_pwd_keys()
        await self._request_auth_keys()

        # SHA256 hash of username + password (not MD5)
        self._hash = sha256((self.username + password).encode()).hexdigest()

        self._generate_aes_key()

        # RSA encrypt password with PKCS1 v1.5 (password uses v1.5, not OAEP)
        encrypted_pwd = self._rsa_v15_encrypt(password, self._pwdNN, self._pwdEE)

        login_data = 'operation=login&password={}&confirm=true'.format(encrypted_pwd)
        encrypted_data = self._aes_encrypt(login_data)

        sign = self._build_login_signature(len(encrypted_data))

        response = await self.session.post(
            'login?form=login', {'sign': sign, 'data': encrypted_data}, use_login_stok=True)

        try:
            decrypted = json.loads(self._aes_decrypt(response['data']))
        except Exception as e:
            raise AuthenticationError(f'Cannot parse login response: {e}') from e

        if not decrypted.get('success'):
            errorcode = decrypted.get('data', {}).get('errorcode', 'unknown')
            raise AuthenticationError(f'Login failed: {errorcode}')

        # httpx.AsyncClient keeps the sysauth cookie from here automatically;
        # only the stok needs to be tracked for building subsequent URLs.
        self.session.stok = decrypted['data']['stok']
        self.session.generation += 1
