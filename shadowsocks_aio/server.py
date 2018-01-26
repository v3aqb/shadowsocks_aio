
import socket
import struct
import logging
import ipaddress
import re
import time
import traceback
import urllib.parse

import asyncio
import asyncio.streams

from hxcrypto import BufEmptyError, InvalidTag, IVError, is_aead, Encryptor


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+):(\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


class ForwardContext:
    def __init__(self):
        self.last_active = time.time()
        # eof recieved
        self.remote_eof = False
        self.local_eof = False
        # link status
        self.writeable = True
        self.readable = True


class HandlerFactory:
    def __init__(self, _class, serverinfo, log_level):
        self._class = _class

        self.serverinfo = serverinfo
        p = urllib.parse.urlparse(serverinfo)
        q = urllib.parse.parse_qs(p.query)
        if p.scheme == 'ss':
            self.PSK, self.method = p.password, p.username
            self.ss_enable = True
        else:
            raise ValueError('bad serverinfo: {}'.format(self.serverinfo))

        self.aead = is_aead(self.method)

        # HTTP proxy only
        proxy = q.get('proxy', [''])[0]
        self.proxy = parse_hostport(proxy) if proxy else None

        self.address = (p.hostname, p.port)

        self.logger = logging.getLogger('ss_%d' % self.address[1])
        self.logger.setLevel(int(q.get('log_level', [log_level])[0]))
        hdr = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                      datefmt='%H:%M:%S')
        hdr.setFormatter(formatter)
        self.logger.addHandler(hdr)

        self.logger.warning('starting server: {}'.format(serverinfo))

    async def handle(self, reader, writer):
        _handler = self._class(self)
        await _handler.handle(reader, writer)


class ShadowsocksHandler:
    bufsize = 8192

    def __init__(self, server):
        self.server = server
        self.logger = server.logger
        self.encryptor = Encryptor(self.server.PSK, self.server.method)
        self._buf = b''

    async def _read(self, size=None):
        if self.server.aead:
            _len = await self.client_reader.readexactly(18)
            if not _len:
                return b''
            _len = self.encryptor.decrypt(_len)
            _len, = struct.unpack("!H", _len)
            ct = await self.client_reader.readexactly(_len+16)
            if not ct:
                return b''
        else:
            size = size or self.bufsize
            ct = await self.client_reader.read(size)
        return self.encryptor.decrypt(ct)

    async def read(self, size=None):
        # compatible with shadowsocks aead
        if not size:
            if self._buf:
                buf, self._buf = self._buf, b''
                return buf
            else:
                return await self._read()
        else:
            while len(self._buf) < size:
                self._buf += (await self._read(size-len(self._buf)))
            _buf, self._buf = self._buf[:size], self._buf[size:]
            return _buf

    async def handle(self, client_reader, client_writer):
        try:
            await self._handle(client_reader, client_writer)
        except Exception as e:
            self.logger.error(repr(e))
            self.logger.error(traceback.format_exc())
        client_writer.close()

    async def _handle(self, client_reader, client_writer):
        self.client_address = client_writer.get_extra_info('peername')
        self.client_reader = client_reader
        self.logger.debug('incoming connection {}'.format(self.client_address))

        try:
            fut = self.client_reader.readexactly(self.encryptor._iv_len)
            iv = await asyncio.wait_for(fut, timeout=10)
            self.encryptor.decrypt(iv)
        except IVError:
            self.logger.error('iv reused, {}'.format(self.client_address))
            await self.play_dead()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            self.logger.warning('iv read failed, {}'.format(self.client_address))
            return

        try:
            fut = self.read(1)
            cmd = await asyncio.wait_for(fut, timeout=10)
        except asyncio.TimeoutError:
            self.logger.warning('read cmd timed out. {}'.format(self.client_address))
            return
        except (ConnectionResetError, asyncio.IncompleteReadError):
            return
        except InvalidTag:
            self.logger.error('InvalidTag while read cmd. {}'.format(self.client_address))
            await self.play_dead()
            return
        cmd = cmd[0]
        self.logger.debug('cmd: {} {}'.format(cmd, self.client_address))

        if cmd in (1, 3, 4):
            # A shadowsocks request
            result = await self.handle_ss(client_reader, client_writer, addr_type=cmd)
            if result:
                await self.play_dead()
            return
        else:
            # TODO: security
            self.logger.error('bad cmd: %s, %s' % (cmd, self.client_address))
            await self.play_dead()
            return

    async def play_dead(self, timeout=1):
        for _ in range(10):
            fut = self.client_reader.read(self.bufsize)
            try:
                await asyncio.wait_for(fut, timeout=1)
            except (asyncio.TimeoutError, ConnectionResetError):
                return

    async def open_connection(self, addr, port, proxy):
        # do security check here
        data = await self.request_is_loopback(addr)
        if data:
            raise ValueError('connect to localhost denied! {}'.format(self.client_address))

        # create connection
        if proxy:
            fut = asyncio.open_connection(proxy[0], proxy[1])
            remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=5)
            s = 'CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\n\r\n'.format(addr, port)
            remote_writer.write(s.encode())
            data = await remote_reader.readuntil(b'\r\n\r\n')
            if b'200' not in data:
                raise IOError(0, 'create tunnel via %s failed!' % proxy)
            return remote_reader, remote_writer

        fut = asyncio.open_connection(addr, port)
        remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=5)
        return remote_reader, remote_writer

    async def handle_ss(self, client_reader, client_writer, addr_type):
        # if error, return 1
        # get header...
        try:
            assert addr_type in (1, 3, 4)
            if addr_type & 15 == 1:
                addr = await self.read(4)
                addr = socket.inet_ntoa(addr)
            elif addr_type & 15 == 3:
                data = await self.read(1)
                addr = await self.read(data[0])
                addr = addr.decode('ascii')
            else:
                data = await self.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, data)
            port = await self.read(2)
            port, = struct.unpack('>H', port)
        except Exception as e:
            self.logger.error('error on read ss header: {} {}'.format(e, self.client_address))
            self.logger.error(traceback.format_exc())
            return 1

        self.logger.info('connect to {}:{} {!r} {!r}'.format(addr, port, self.client_address, self.server.proxy))

        try:
            remote_reader, remote_writer = await self.open_connection(addr, port, self.server.proxy)
        except Exception as e:
            self.logger.error('connect to {}:{} failed! {!r}'.format(addr, port, e))
            return

        context = ForwardContext()

        tasks = [self.ss_forward_A(client_reader, remote_writer, self.encryptor.decrypt, context),
                 self.ss_forward_B(remote_reader, client_writer, self.encryptor.encrypt, context),
                 ]
        try:
            await asyncio.wait(tasks)
        except Exception as e:
            self.logger.error(repr(e))
            self.logger.error(traceback.format_exc())
        remote_writer.close()

    async def ss_forward_A(self, read_from, write_to, cipher, context, timeout=60):
        # data from ss client
        while True:
            try:
                fut = self.read()
                data = await asyncio.wait_for(fut, timeout=5)
                context.last_active = time.time()
            except asyncio.TimeoutError:
                if time.time() - context.last_active > timeout or context.remote_eof:
                    data = b''
                else:
                    continue
            except (BufEmptyError, asyncio.IncompleteReadError, InvalidTag, ConnectionResetError, OSError):
                data = b''

            if not data:
                break
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionResetError:
                context.local_eof = True
                return
        context.local_eof = True
        try:
            write_to.write_eof()
        except (ConnectionResetError, OSError):
            pass

    async def ss_forward_B(self, read_from, write_to, cipher, context, timeout=60):
        # data from remote
        while True:
            try:
                fut = read_from.read(self.bufsize)
                data = await asyncio.wait_for(fut, timeout=5)
                context.last_active = time.time()
            except asyncio.TimeoutError:
                if time.time() - context.last_active > timeout or context.local_eof:
                    data = b''
                else:
                    continue
            except (ConnectionResetError, OSError):
                data = b''

            if not data:
                break
            data = cipher(data)
            try:
                write_to.write(data)
                await write_to.drain()
            except ConnectionResetError:
                context.remote_eof = True
                return
        context.remote_eof = True
        # write_to.write_eof()

    async def get_ip_address(self, host):
        try:
            return ipaddress(host)
        except Exception:
            try:
                return ipaddress((await self.loop.getaddrinfo(host))[0][4][1])
            except Exception:
                return ipaddress('0.0.0.0')

    async def request_is_loopback(self, addr):
        try:
            ip = await self.get_ip_address(addr)
            self.logger.debug('requesting {}'.format(ip))
            if ip.is_loopback:
                return ip
        except Exception:
            pass
