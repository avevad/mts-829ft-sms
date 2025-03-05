import argparse
import asyncio
import json
from enum import Enum
import os
from typing import Optional

import aiohttp

from mts_829ft_sms.api import ModemAPI

WEBHOOK_URL = lambda: os.environ.get('MTS_829FT_WEBHOOK_URL', None)


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
            return json.dumps(sms.raw)

        assert False, 'Unknown format'


class SmsReceiver:
    _webhook_url: Optional[str]
    _sms_format: SmsFormat

    def __init__(self, webhook_url: Optional[str], sms_format: SmsFormat):
        self._webhook_url = webhook_url or WEBHOOK_URL()
        self._sms_format = sms_format

    async def handle_sms(self, sms: ModemAPI.Sms):
        msg = self._sms_format.format_sms(sms)

        print(msg)

        if self._webhook_url is not None:
            async with aiohttp.ClientSession() as session, session.post(
                    self._webhook_url,
                    data=msg
            ):
                pass


async def receive_loop(api: ModemAPI, interval: float, receiver: SmsReceiver):
    latest_count = await api.count_sms()
    old_pairs = set([(sms.index, sms.date) for sms in (await api.list_sms())])

    while True:
        count = await api.count_sms()

        if count.local_inbox <= latest_count.local_inbox:
            continue

        await asyncio.sleep(interval)

        latest_count = count
        messages = await api.list_sms()
        new_messages = [sms for sms in messages if (sms.index, sms.date) not in old_pairs]
        for sms in new_messages:
            await receiver.handle_sms(sms)
            old_pairs.add((sms.index, sms.date))

        await asyncio.sleep(interval)


async def main_loop():
    parser = argparse.ArgumentParser(description='MTS 829FT SMS Client')
    sub = parser.add_subparsers(dest='action', required=True)

    parser_receive = sub.add_parser('receive', help='Continuously receive SMS messages')
    parser_receive.add_argument('--interval', '-i', type=float, default=1, help='Interval between checks (in seconds)')
    parser_receive.add_argument('--format', '-f', type=SmsFormat, default=SmsFormat.PLAIN, choices=list(SmsFormat),
                                help='Output format')
    parser_receive.add_argument('--webhook', '-w', type=str, required=False, help='Webhook URL to send messages to')

    args = parser.parse_args()

    async with ModemAPI() as api:
        await api.authenticate()

        if args.action == 'receive':
            receiver = SmsReceiver(args.webhook, args.format)
            await receive_loop(api, args.interval, receiver)
