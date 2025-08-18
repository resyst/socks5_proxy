import socket
import asyncio
import winloop

winloop.install()

async def handle_client(reader, writer):
    remote_writer = None
    try:
        sock = writer.transport.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        writer.transport.set_write_buffer_limits(high=8192, low=2048)

        if not (version := await reader.readexactly(1)) or version[0] != 5:
            return writer.close()

        if not (nmethods_byte := await reader.readexactly(1)):
            return writer.close()
        nmethods = nmethods_byte[0]
        methods = await reader.readexactly(nmethods)

        if 0 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return writer.close()

        writer.write(b'\x05\x00')
        await writer.drain()

        request = await reader.readexactly(4)
        ver, cmd, rsv, atyp = request

        if ver != 5:
            return writer.close()

        match atyp:
            case 1:
                addr_bytes = await reader.readexactly(4)
                addr = socket.inet_ntoa(addr_bytes)
                conn_family = socket.AF_INET
            case 3:
                domain_len_byte = await reader.readexactly(1)
                domain_len = domain_len_byte[0]
                addr_bytes = await reader.readexactly(domain_len)
                addr = addr_bytes.decode('utf-8')
                conn_family = 0
            case 4:
                addr_bytes = await reader.readexactly(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
                conn_family = socket.AF_INET6
            case _:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return writer.close()

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, 'big')

        match cmd:
            case 1:
                rep = 0
                atyp_reply = 1
                bind_addr_bytes = b'\x00\x00\x00\x00'
                bind_port = 0
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(
                        addr, port, family=conn_family, limit=8192
                    )
                    remote_writer.transport.set_write_buffer_limits(high=8192, low=2048)
                    remote_sock = remote_writer.transport.get_extra_info('socket')
                    remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
                    remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                    remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)

                    sockname = remote_writer.get_extra_info('sockname')
                    local_addr, local_port, *_ = sockname
                    remote_family = remote_sock.family
                    if remote_family == socket.AF_INET:
                        atyp_reply = 1
                        bind_addr_bytes = socket.inet_pton(socket.AF_INET, local_addr)
                    elif remote_family == socket.AF_INET6:
                        atyp_reply = 4
                        bind_addr_bytes = socket.inet_pton(socket.AF_INET6, local_addr)
                    bind_port = local_port
                except OSError as e:
                    print(f"Failed to connect to {addr}:{port} (atyp={atyp}): {e}")
                    rep = 1
                    atyp_reply = 4 if atyp == 4 else 1
                    bind_addr_bytes = b'\x00' * (16 if atyp == 4 else 4)

                reply = b'\x05' + bytes([rep, 0, atyp_reply]) + bind_addr_bytes + bind_port.to_bytes(2, 'big')
                writer.write(reply)
                await writer.drain()

                if rep != 0:
                    writer.close()
                    if remote_writer:
                        remote_writer.close()
                    return

                async def relay(reader_from, writer_to):
                    try:
                        while data := await reader_from.read(8192):
                            writer_to.write(data)
                            await writer_to.drain()
                    except (OSError, asyncio.CancelledError):
                        pass
                    finally:
                        try:
                            writer_to.write_eof()
                        except OSError:
                            pass

                await asyncio.gather(
                    relay(reader, remote_writer),
                    relay(remote_reader, writer)
                )

            case _:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                return writer.close()

    except (OSError, asyncio.CancelledError) as e:
        print(f"Error handling client: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        if remote_writer:
            remote_writer.close()
            try:
                await remote_writer.wait_closed()
            except OSError:
                pass

async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 1080, limit=8192)
    print("SOCKS5 proxy listening on port 1080 (IPv4 loopback)")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down due to KeyboardInterrupt")
