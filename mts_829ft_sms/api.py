import base64
import hashlib
import os
from enum import Enum, IntEnum
from http.client import responses
from typing import Optional

import aiohttp

import xmltodict
from attr import dataclass

WEBUI_URL = lambda: os.environ.get('MTS_829FT_URL', 'http://192.168.8.1')
WEBUI_LOGIN = lambda: os.environ.get('MTS_829FT_LOGIN', 'admin')
WEBUI_PASSWORD = lambda: os.environ['MTS_829FT_PASSWORD']


class ModemAPI:
    _webui_url: str
    _cookie_jar: aiohttp.CookieJar
    _client_session: aiohttp.ClientSession

    class ErrorCode(IntEnum):
        UNKNOWN = -1
        UNAUTHORIZED = 125002
        INVALID_METHOD = 100005
        UNKNOWN_REQUEST = 100002

    class Error(Exception):
        def __init__(self, code: int, message: str):
            self.code = code
            self.message = message
            self.err_code = ModemAPI.ErrorCode(code) if code in ModemAPI.ErrorCode else \
                ModemAPI.ErrorCode.UNKNOWN
            super().__init__(f'{self.err_code.name}[{code}] {message}')

        @staticmethod
        def raise_for_response(obj: dict):
            if 'error' in obj:
                err_code = int(obj['error']['code'])
                msg = str(obj['error']['message'] or "")
                raise ModemAPI.Error(err_code, msg)

    def __init__(
            self, webui_url: Optional[str] = None
    ):
        self._webui_url = webui_url or WEBUI_URL()
        self._cookie_jar = aiohttp.CookieJar(unsafe=True)
        self._client_session = aiohttp.ClientSession(cookie_jar=self._cookie_jar)

    async def __aenter__(self) -> 'ModemAPI':
        self._client_session = await self._client_session.__aenter__()
        async with self._client_session.get(self._webui_url):
            pass
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._client_session.__aexit__(exc_type, exc_val, exc_tb)

    async def _do_xml_request(
            self, method: str, path: str, headers: Optional[dict] = None, data: Optional[dict] = None
    ) -> dict:
        async with self._client_session.request(
                method, self._webui_url + path, data=xmltodict.unparse(data) if data else None, headers=headers or {}
        ) as response:
            response.raise_for_status()
            obj = xmltodict.parse(await response.text())
            self.Error.raise_for_response(obj)
            return obj

    async def get_onetime_token(self) -> str:
        response = await self._do_xml_request('get', '/api/webserver/SesTokInfo')
        return response['response']['TokInfo']

    async def authenticate(self, webui_login: Optional[str] = None, webui_password: Optional[str] = None):
        webui_login = webui_login or WEBUI_LOGIN()
        webui_password = webui_password or WEBUI_PASSWORD()
        token = await self.get_onetime_token()
        # encrypted password is calculated as following (taken from mts-829ft-sms/main.js):
        # base64encode(SHA256(name + base64encode(SHA256($('#password').val())) + g_requestVerificationToken[0]))
        password_enc = base64.b64encode(hashlib.sha256((webui_login + base64.b64encode(hashlib.sha256(
            webui_password.encode()).hexdigest().encode()).decode() + token).encode()).hexdigest().encode()).decode()
        await self._do_xml_request(
            'post', '/api/user/login',
            data={'request': {'Username': webui_login, 'Password': password_enc, 'password_type': 4}},
            headers={'__RequestVerificationToken': token}
        )

    @dataclass
    class Sms:
        index: int
        phone: str
        content: str
        date: str
        raw: dict

        @staticmethod
        def from_raw(raw: dict) -> 'ModemAPI.Sms':
            return ModemAPI.Sms(
                index=int(raw['Index']),
                phone=raw['Phone'],
                content=raw['Content'],
                date=raw['Date'],
                raw=raw
            )

    async def list_sms(
            self, page_index: int = 1, read_count: int = 20, box_type: int = 1,
            sort_type: int = 0, ascending: int = 0, unread_preferred: int = 0
    ) -> list[Sms]:
        token = await self.get_onetime_token()
        res = await self._do_xml_request(
            'post', '/api/sms/sms-list',
            data={'request': {
                'PageIndex': page_index, 'ReadCount': read_count, 'BoxType': box_type,
                'SortType': sort_type, 'Ascending': ascending, 'UnreadPreferred': unread_preferred
            }},
            headers={'__RequestVerificationToken': token}
        )
        msgs = [self.Sms.from_raw(sms) for sms in res['response']['Messages']['Message']]
        return msgs

    @dataclass
    class SmsCount:
        local_inbox: int
        raw: dict

        @staticmethod
        def from_raw(raw: dict) -> 'ModemAPI.SmsCount':
            return ModemAPI.SmsCount(
                local_inbox=int(raw['LocalInbox']),
                raw=raw
            )

    async def count_sms(self) -> SmsCount:
        token = await self.get_onetime_token()
        res = await self._do_xml_request(
            'get', '/api/sms/sms-count',
            headers={'__RequestVerificationToken': token}
        )
        return self.SmsCount.from_raw(res['response'])
