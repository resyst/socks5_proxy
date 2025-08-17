import socket
import asyncio
import sys
import signal

async def handle_client(reader, writer):
    remote_writer = None
    try:
        sock = writer.transport.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
        family = sock.family
        if family == socket.AF_INET:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 16)  # Low delay
            except OSError:
                pass
        elif family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, 16)  # Traffic class for IPv6
            except OSError:
                pass

        # Greeting: version and methods
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

        # Support only no authentication (0x00)
        if 0 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            writer.close()
            return

        # Select no authentication
        writer.write(b'\x05\x00')
        await writer.drain()

        # Request
        request = await reader.readexactly(4)

        ver, cmd, rsv, atyp = request  # Since request is bytes, this unpacks to ints

        if ver != 5:
            writer.close()
            return

        # Address - Support IPv4, IPv6, and Domain
        if atyp == 1:  # IPv4
            addr_bytes = await reader.readexactly(4)
            addr = socket.inet_ntoa(addr_bytes)
            conn_family = socket.AF_INET
        elif atyp == 3:  # Domain name
            domain_len_byte = await reader.readexactly(1)
            domain_len = domain_len_byte[0]
            addr_bytes = await reader.readexactly(domain_len)
            addr = addr_bytes.decode('utf-8')
            conn_family = 0  # Let system decide
        elif atyp == 4:  # IPv6
            addr_bytes = await reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            conn_family = socket.AF_INET6
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
            await writer.drain()
            writer.close()
            return

        port_bytes = await reader.readexactly(2)
        port = int.from_bytes(port_bytes, 'big')

        # Handle command - Only TCP CONNECT
        if cmd == 1:  # CONNECT (TCP)
            rep = 0
            atyp_reply = 1  # Default for failure
            bind_addr_bytes = b'\x00\x00\x00\x00'
            bind_port = 0
            try:
                remote_reader, remote_writer = await asyncio.open_connection(addr, port, family=conn_family)
                remote_sock = remote_writer.transport.get_extra_info('socket')
                remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
                remote_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
                remote_family = remote_sock.family
                if remote_family == socket.AF_INET:
                    try:
                        remote_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 16)  # Low delay
                    except OSError:
                        pass
                elif remote_family == socket.AF_INET6:
                    try:
                        remote_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, 16)  # Traffic class for IPv6
                    except OSError:
                        pass

                # Get actual bound address for reply
                local_addr, local_port = remote_writer.get_extra_info('sockname')
                if remote_family == socket.AF_INET:
                    atyp_reply = 1
                    bind_addr_bytes = socket.inet_pton(socket.AF_INET, local_addr)
                elif remote_family == socket.AF_INET6:
                    atyp_reply = 4
                    bind_addr_bytes = socket.inet_pton(socket.AF_INET6, local_addr)
                bind_port = local_port
            except OSError as e:
                print(f"Failed to connect to {addr}:{port} (atyp={atyp}): {e}")
                rep = 1  # General failure

            # Send reply
            reply = (b'\x05' + bytes([rep, 0, atyp_reply]) +
                     bind_addr_bytes + bind_port.to_bytes(2, 'big'))
            writer.write(reply)
            await writer.drain()

            if rep != 0:
                writer.close()
                if remote_writer:
                    remote_writer.close()
                return

            # Relay data concurrently
            async def relay(reader_from, writer_to):
                try:
                    while True:
                        data = await reader_from.read(65536)
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

        else:
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
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
            pass  # Ignore connection errors during close
        if remote_writer:
            remote_writer.close()
            try:
                await remote_writer.wait_closed()
            except OSError:
                pass  # Ignore connection errors during close

async def shutdown(sig, loop, server):
    if sig:
        print(f"Received exit signal {sig.name}...")
    else:
        print("Received KeyboardInterrupt")
    print("Shutting down")
    server.close()
    await server.wait_closed()
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    server = loop.run_until_complete(asyncio.start_server(handle_client, '127.0.0.1', 1080))
    print(f"SOCKS5 proxy listening on port 1080 (IPv4 loopback)")
    if sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(shutdown(signal.SIGINT, loop, server)))
        loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(shutdown(signal.SIGTERM, loop, server)))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        if sys.platform == 'win32':
            loop.run_until_complete(shutdown(None, loop, server))
    finally:
        loop.close()
