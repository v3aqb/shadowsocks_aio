import os
import sys
import yaml
import asyncio
import argparse

from .server import HandlerFactory, ShadowsocksHandler

from concurrent.futures import ThreadPoolExecutor

if sys.platform == 'win32':
    loop = asyncio.ProactorEventLoop()
    asyncio.set_event_loop(loop)

parser = argparse.ArgumentParser()
parser.add_argument('-c', required=True, help="config file")
args = parser.parse_args()

if not os.path.exists(args.c):
    sys.stderr.write('config file {} not exist!\n'.format(args.c))
    sys.exit()
else:
    with open(args.c, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
    servers = cfg['servers']
    log_level = cfg['log_level'] if 'log_level' in cfg else 20

loop = asyncio.get_event_loop()
loop.set_default_executor(ThreadPoolExecutor(20))

for s in servers:
    handler = HandlerFactory(ShadowsocksHandler, serverinfo=s, log_level=log_level)
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handler.handle, handler.address[0], handler.address[1], loop=loop)
    server = loop.run_until_complete(coro)

loop.run_forever()
