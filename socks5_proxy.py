import socket
import asyncio
import winloop

winloop.install()

async def handle_client(reader, writer):
    remote_writer = None
    try:
        sock = writer.transport.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)
        writer.transport.set_write_buffer_limits(high=16384, low=4096)

        version = await reader.readexactly(1)
        if not version or version[0] != 5:
            writer.close()
            return

        nmethods_byte = await reader.readexactly(1)
        if not nmethods_byte:
            writer.close()
            return
        nmethods = nmethods_byte[0]
        methods = await reader.readexactly(nmethods)

        if 0 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
            return

        writer.write(b'\x05\x00')
        await writer.drain()

        request = await reader.readexactly(4)

        ver, cmd, rsv, atyp = request

        if ver != 5:
            writer.close()
            return

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
                writer.close()
                return

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, 'big')

        match cmd:
            case 1:
                rep = 0
                atyp_reply = 1
                bind_addr_bytes = b'\x00\x00\x00\x00'
                bind_port = 0
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(addr, port, family=conn_family)
                    remote_writer.transport.set_write_buffer_limits(high=16384, low=4096)
                    remote_sock = remote_writer.transport.get_extra_info('socket')
                    remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 128 * 1024)
                    remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 128 * 1024)

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
                    if atyp == 4:
                        atyp_reply = 4
                        bind_addr_bytes = b'\x00' * 16
                    else:
                        atyp_reply = 1
                        bind_addr_bytes = b'\x00' * 4

                reply = (b'\x05' + bytes([rep, 0, atyp_reply]) +
                         bind_addr_bytes + bind_port.to_bytes(2, 'big'))
                writer.write(reply)
                await writer.drain()

                if rep != 0:
                    writer.close()
                    if remote_writer:
                        remote_writer.close()
                    return

                async def relay(reader_from, writer_to):
                    try:
                        while True:
                            data = await reader_from.read(131072)
                            if not data:
                                break
                            writer_to.write(data)
                            await writer_to.drain()
                    except Exception:
                        pass
                    finally:
                        try:
                            writer_to.transport.get_extra_info('socket').shutdown(socket.SHUT_WR)
                        except Exception:
                            pass

                await asyncio.gather(
                    relay(reader, remote_writer),
                    relay(remote_reader, writer)
                )

            case _:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                writer.close()
                return

    except Exception as e:
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
    server = await asyncio.start_server(handle_client, '127.0.0.1', 1080)
    print(f"SOCKS5 proxy listening on port 1080 (IPv4 loopback)")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down due to KeyboardInterrupt")
