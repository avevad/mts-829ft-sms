import argparse
import asyncio
import json
import re
from enum import StrEnum
from typing import Optional, Callable, Coroutine

import aiohttp
import yaml

from mts_829ft_sms.api import ModemAPI


class SmsFormat(StrEnum):
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
    _receivers: list[(Callable[[ModemAPI.Sms], bool], list[Callable[[ModemAPI.Sms], Coroutine[None, None, None]]])]

    def __init__(self, receivers: list[
        (Callable[[ModemAPI.Sms], bool], list[Callable[[ModemAPI.Sms], Coroutine[None, None, None]]])]):
        self._receivers = receivers

    async def handle_sms(self, sms: ModemAPI.Sms):
        for pred, receivers in self._receivers:
            if pred(sms):
                for receiver in receivers:
                    await receiver(sms)
                break

    @staticmethod
    def pred_from_config(from_regex: Optional[str], content_regex: Optional[str]):
        def pred(sms: ModemAPI.Sms) -> bool:
            if from_regex is not None and not re.search(re.compile(from_regex, re.UNICODE), sms.phone):
                return False

            if content_regex is not None and not re.search(re.compile(content_regex, re.UNICODE), sms.content):
                return False

            return True

        return pred

    @staticmethod
    def stdout_handler_from_config(stdout_dict: dict):
        async def handler(sms: ModemAPI.Sms):
            print(SmsFormat(stdout_dict.get('format', SmsFormat.PLAIN)).format_sms(sms))

        return handler

    @staticmethod
    def webhook_handler_from_config(webhook_dict: dict):
        headers = {}
        if webhook_dict.get('auth', None) is not None:
            headers['Authorization'] = webhook_dict['auth']
        if webhook_dict.get('format', SmsFormat.PLAIN) == SmsFormat.JSON:
            headers['Content-Type'] = 'application/json'

        async def handler(sms: ModemAPI.Sms):
            async with aiohttp.ClientSession() as session, session.post(
                    webhook_dict['url'],
                    data=SmsFormat(webhook_dict['format']).format_sms(sms),
                    headers=headers
            ) as response:
                pass

        return handler

    @staticmethod
    def handlers_from_config(to_dict: dict) -> list[Callable[[ModemAPI.Sms], Coroutine[None, None, None]]]:
        handlers = []

        if to_dict.get('stdout', None) is not None:
            handlers.append(SmsReceiver.stdout_handler_from_config(to_dict['stdout']))

        if to_dict.get('webhooks', None) is not None:
            handlers.extend([SmsReceiver.webhook_handler_from_config(webhook) for webhook in to_dict['webhooks']])

        return handlers

    @staticmethod
    def from_config(config: list[dict]):
        receivers = []

        for receiver in config:
            pred = SmsReceiver.pred_from_config(receiver.get('from', None), receiver.get('content', None))
            handlers = SmsReceiver.handlers_from_config(receiver['to'])
            receivers.append((pred, handlers))

        return SmsReceiver(receivers)


async def receive_loop(api: ModemAPI, interval: float, receiver: SmsReceiver, delete: bool):
    latest_count = await api.count_sms()
    old_pairs = set([(sms.index, sms.date) for sms in (await api.list_sms())])

    while True:
        await asyncio.sleep(interval)
        count = await api.count_sms()

        if count.local_inbox <= latest_count.local_inbox:
            continue

        latest_count = count

        await asyncio.sleep(2 * interval)  # for safety
        messages1 = await api.list_sms()  # for safety
        messages = await api.list_sms()

        new_messages = [sms for sms in messages if (sms.index, sms.date) not in old_pairs]
        for sms in new_messages:
            await receiver.handle_sms(sms)
            old_pairs.add((sms.index, sms.date))

        if delete:
            await api.delete_sms(new_messages)
            latest_count.local_inbox -= len(new_messages)


async def main_loop():
    parser = argparse.ArgumentParser(description='MTS 829FT SMS Client')
    sub = parser.add_subparsers(dest='action', required=True)

    parser_receive = sub.add_parser('receive', help='Continuously receive SMS messages')
    parser_receive.add_argument('--interval', '-i', type=float, default=1, help='Interval between checks (in seconds)')
    parser_receive.add_argument('--config', '-c', type=str, default='config.yaml', help='Config file')
    parser_receive.add_argument('--delete', '-d', action='store_true', help='Delete messages after receiving')

    args = parser.parse_args()

    async with ModemAPI() as api:
        await api.authenticate()

        if args.action == 'receive':
            with open(args.config) as f:
                config = yaml.safe_load(f)
            receiver = SmsReceiver.from_config(config)
            await receive_loop(api, args.interval, receiver, args.delete)
