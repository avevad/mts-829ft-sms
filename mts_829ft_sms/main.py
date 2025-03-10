import argparse
import asyncio
import json
import re
from enum import Enum
import os
from typing import Optional

import aiohttp

from mts_829ft_sms.api import ModemAPI

WEBHOOK_URL = lambda: os.environ.get('MTS_829FT_WEBHOOK_URL', None)
WEBHOOK_AUTH = lambda: os.environ.get('MTS_829FT_WEBHOOK_AUTH', None)


class SmsFormat(Enum):
    PLAIN = 'plain'
    JSON = 'json'

    def format_sms(self, sms: ModemAPI.Sms) -> str:
        if self == self.PLAIN:
            return (
                f'From: {sms.phone}\n'
                f'Date: {sms.date}\n'
                f'\n'
                f'{sms.content}'
            )

        if self == self.JSON:
            return json.dumps(sms.raw, ensure_ascii=False)

        assert False, 'Unknown format'

class SmsReceiver:
    _webhook_url: Optional[str]
    _webhook_auth: Optional[str]
    _sms_format: SmsFormat
    _sender_regex: Optional[re.Pattern]
    _content_regex: Optional[re.Pattern]

    def __init__(
            self, webhook_url: Optional[str], sms_format: SmsFormat,
            sender_regex: Optional[str] = None, content_regex: Optional[str] = None
    ):
        self._webhook_url = webhook_url or WEBHOOK_URL()
        self._webhook_auth = WEBHOOK_AUTH()
        self._sms_format = sms_format
        self._sender_regex = re.compile(sender_regex, re.UNICODE) if sender_regex is not None else None
        self._content_regex = re.compile(content_regex, re.UNICODE) if content_regex is not None else None

    async def handle_sms(self, sms: ModemAPI.Sms):
        if self._sender_regex is not None and not self._sender_regex.search(sms.phone):
            return

        if self._content_regex is not None and not self._content_regex.search(sms.content):
            return

        msg = self._sms_format.format_sms(sms)

        print(msg)

        if self._webhook_url is not None:
            headers = {}
            if self._webhook_auth is not None:
                headers['Authorization'] = self._webhook_auth
            if self._sms_format == SmsFormat.JSON:
                headers['Content-Type'] = 'application/json'
            async with aiohttp.ClientSession() as session, session.post(
                    self._webhook_url,
                    data=msg,
                    headers=headers
            ) as response:
                pass


async def receive_loop(api: ModemAPI, interval: float, receiver: SmsReceiver):
    latest_count = await api.count_sms()
    old_pairs = set([(sms.index, sms.date) for sms in (await api.list_sms())])

    while True:
        await asyncio.sleep(interval)
        count = await api.count_sms()

        if count.local_inbox <= latest_count.local_inbox:
            continue

        latest_count = count

        await asyncio.sleep(2 * interval) # for safety
        messages1 = await api.list_sms() # for safety
        messages = await api.list_sms()

        new_messages = [sms for sms in messages if (sms.index, sms.date) not in old_pairs]
        for sms in new_messages:
            await receiver.handle_sms(sms)
            old_pairs.add((sms.index, sms.date))


async def main_loop():
    parser = argparse.ArgumentParser(description='MTS 829FT SMS Client')
    sub = parser.add_subparsers(dest='action', required=True)

    parser_receive = sub.add_parser('receive', help='Continuously receive SMS messages')
    parser_receive.add_argument('--interval', '-i', type=float, default=1, help='Interval between checks (in seconds)')
    parser_receive.add_argument('--format', '-f', type=SmsFormat, default=SmsFormat.PLAIN, choices=list(SmsFormat), help='Output format')
    parser_receive.add_argument('--webhook', '-w', type=str, required=False, help='Webhook URL to send messages to')
    parser_receive.add_argument('--content-regex', '-c', type=str, required=False, help='Regular expression to filter messages by content')
    parser_receive.add_argument('--sender-regex', '-s', type=str, required=False, help='Regular expression to filter messages by sender')

    args = parser.parse_args()

    async with ModemAPI() as api:
        await api.authenticate()

        if args.action == 'receive':
            receiver = SmsReceiver(args.webhook, args.format, args.sender_regex, args.content_regex)
            await receive_loop(api, args.interval, receiver)
