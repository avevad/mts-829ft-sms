from .main import main_loop
from .api import ModemAPI


def main_loop_sync():
    import asyncio
    asyncio.run(main_loop())
