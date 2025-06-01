import asyncio
import socket
import struct
import logging
import time
import ssl
import json
from enum import IntEnum
from urllib.parse import urlparse
import ipaddress

# --- 配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger("Socks5Proxy")

# --- 常量 ---
SOCKS_VERSION = 0x05
BUFFER_SIZE = 4096
COOLDOWN_MULTIPLIER = 300
MIN_FAILURE_COUNT = 3
DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_UDP_TIMEOUT = 120

# --- 全局配置 ---
ENABLE_USERNAME_PASSWORD_AUTH = False
VALID_CREDENTIALS = {}

# --- 枚举类 ---
class SocksAuthMethod(IntEnum):
    NO_AUTHENTICATION_REQUIRED = 0x00
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE_METHODS = 0xFF

class SocksCommand(IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

class SocksAddressType(IntEnum):
    IPV4 = 0x01
    DOMAINNAME = 0x03
    IPV6 = 0x04

class SocksReplyStatus(IntEnum):
    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08

class UsernamePasswordAuthStatus(IntEnum):
    SUCCESS = 0x00
    FAILURE = 0x01

# --- 路由健康管理 ---
class RouteHealth:
    def __init__(self):
        self.fail_count = 0
        self.cooldown_until = 0

    def mark_success(self):
        self.fail_count = 0
        self.cooldown_until = 0

    def mark_failure(self):
        self.fail_count += 1
        if self.fail_count >= MIN_FAILURE_COUNT:
            self.cooldown_until = time.time() + COOLDOWN_MULTIPLIER * self.fail_count

    def is_healthy(self):
        return time.time() > self.cooldown_until

class HostRouteManager:
    def __init__(self):
        self._health = {}

    def get(self, host):
        if host not in self._health:
            self._health[host] = RouteHealth()
        return self._health[host]

    def save_health_status(self):
        try:
            data = [{host: {'fail_count': health.fail_count, 'cooldown_until': health.cooldown_until}} 
                   for host, health in self._health.items() if health.fail_count > 0]
            with open('route_health.json', 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存健康状态失败: {e}")

host_route_manager = HostRouteManager()

# --- 工具函数 ---
async def read_exact(reader: asyncio.StreamReader, n_bytes: int) -> bytes:
    """精确读取指定字节数"""
    try:
        return await reader.readexactly(n_bytes)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        raise asyncio.IncompleteReadError(b'', n_bytes)

async def send_socks_reply(writer: asyncio.StreamWriter, status: SocksReplyStatus, 
                          atyp: SocksAddressType = SocksAddressType.IPV4,
                          bind_addr: str = "0.0.0.0", bind_port: int = 0):
    """发送SOCKS5回复"""
    try:
        if atyp == SocksAddressType.IPV4:
            addr_bytes = socket.inet_pton(socket.AF_INET, bind_addr)
        elif atyp == SocksAddressType.IPV6:
            addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
        elif atyp == SocksAddressType.DOMAINNAME:
            encoded = bind_addr.encode('utf-8')
            addr_bytes = struct.pack('!B', len(encoded)) + encoded
        else:
            atyp = SocksAddressType.IPV4
            addr_bytes = socket.inet_pton(socket.AF_INET, "0.0.0.0")
            bind_port = 0

        reply = struct.pack('!BBBB', SOCKS_VERSION, status.value, 0x00, atyp.value)
        reply += addr_bytes + struct.pack('!H', bind_port)
        
        writer.write(reply)
        await writer.drain()
    except Exception as e:
        logger.warning(f"发送SOCKS回复失败: {e}")

async def pipe_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                   source_desc: str, dest_desc: str, close_on_exit: bool = True):
    """数据管道传输"""
    try:
        while not reader.at_eof() and not writer.is_closing():
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        logger.debug(f"管道关闭: {source_desc} -> {dest_desc}")
    except Exception as e:
        logger.error(f"管道错误: {e}")
    finally:
        if close_on_exit and not writer.is_closing():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

# --- 连接函数 ---
async def try_direct_connection(host: str, port: int, timeout: float):
    """尝试直接连接"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        logger.debug(f"直连成功: {host}:{port}")
        return reader, writer
    except Exception as e:
        logger.debug(f"直连失败: {host}:{port} - {e}")
        return None, None

async def create_tls_connection(host: str, port: int, timeout: float):
    """创建TLS连接"""
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context), timeout=timeout
        )
        logger.debug(f"TLS连接成功: {host}:{port}")
        return reader, writer
    except Exception as e:
        logger.debug(f"TLS连接失败: {host}:{port} - {e}")
        return None, None

def parse_proxy_url(proxy_url: str) -> dict:
    """解析代理URL"""
    try:
        if "://" not in proxy_url:
            proxy_url = "socks5://" + proxy_url
        
        parsed = urlparse(proxy_url)
        return {
            'host': parsed.hostname,
            'port': parsed.port or 1080,
            'username': parsed.username,
            'password': parsed.password,
            'use_tls': parsed.scheme.lower() in ['socks5+tls', 'socks5tls']
        }
    except Exception as e:
        logger.error(f"解析代理URL失败: {e}")
        return {}

# --- 认证相关 ---
async def handle_username_password_auth(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                       client_addr: str) -> bool:
    """处理用户名密码认证"""
    try:
        header = await read_exact(reader, 2)
        ver, ulen = struct.unpack('!BB', header)
        
        if ver != 0x01 or ulen == 0:
            return False
        
        username = (await read_exact(reader, ulen)).decode('utf-8', errors='replace')
        plen = (await read_exact(reader, 1))[0]
        password = (await read_exact(reader, plen)).decode('utf-8', errors='replace')
        
        success = username in VALID_CREDENTIALS and VALID_CREDENTIALS[username] == password
        status = UsernamePasswordAuthStatus.SUCCESS if success else UsernamePasswordAuthStatus.FAILURE
        
        writer.write(struct.pack('!BB', 0x01, status.value))
        await writer.drain()
        
        if success:
            logger.info(f"{client_addr}: 用户 '{username}' 认证成功")
        else:
            logger.warning(f"{client_addr}: 用户 '{username}' 认证失败")
        
        return success
    except Exception as e:
        logger.warning(f"{client_addr}: 认证失败 - {e}")
        return False

async def handle_socks_authentication(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                    client_addr: str) -> bool:
    """处理SOCKS认证"""
    try:
        header = await read_exact(reader, 2)
        ver, nmethods = struct.unpack('!BB', header)
        
        if ver != SOCKS_VERSION or nmethods == 0:
            return False
        
        methods = await read_exact(reader, nmethods)
        
        # 选择认证方法
        if ENABLE_USERNAME_PASSWORD_AUTH and SocksAuthMethod.USERNAME_PASSWORD.value in methods:
            selected = SocksAuthMethod.USERNAME_PASSWORD
        elif SocksAuthMethod.NO_AUTHENTICATION_REQUIRED.value in methods:
            selected = SocksAuthMethod.NO_AUTHENTICATION_REQUIRED
        else:
            writer.write(struct.pack('!BB', SOCKS_VERSION, SocksAuthMethod.NO_ACCEPTABLE_METHODS.value))
            await writer.drain()
            return False
        
        writer.write(struct.pack('!BB', SOCKS_VERSION, selected.value))
        await writer.drain()
        
        if selected == SocksAuthMethod.USERNAME_PASSWORD:
            return await handle_username_password_auth(reader, writer, client_addr)
        
        return True
    except Exception as e:
        logger.error(f"{client_addr}: 认证错误 - {e}")
        return False

async def parse_socks_address_port(reader: asyncio.StreamReader, client_addr: str):
    """解析SOCKS地址和端口"""
    try:
        atyp_val = (await read_exact(reader, 1))[0]
        atyp = SocksAddressType(atyp_val)
        
        if atyp == SocksAddressType.IPV4:
            addr_bytes = await read_exact(reader, 4)
            host = socket.inet_ntop(socket.AF_INET, addr_bytes)
        elif atyp == SocksAddressType.DOMAINNAME:
            domain_len = (await read_exact(reader, 1))[0]
            if domain_len == 0:
                return None, None, None
            host = (await read_exact(reader, domain_len)).decode('utf-8', errors='replace')
        elif atyp == SocksAddressType.IPV6:
            addr_bytes = await read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            return None, None, None
        
        port = struct.unpack('!H', await read_exact(reader, 2))[0]
        return atyp, host, port
    except Exception as e:
        logger.warning(f"{client_addr}: 解析地址失败 - {e}")
        return None, None, None

# --- 代理连接 ---
async def authenticate_with_proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                username: str, password: str, timeout: float) -> bool:
    """向上游代理认证"""
    try:
        auth_request = struct.pack('!BB', 0x01, len(username)) + username.encode('utf-8')
        auth_request += struct.pack('!B', len(password)) + password.encode('utf-8')
        
        writer.write(auth_request)
        await writer.drain()
        
        response = await asyncio.wait_for(read_exact(reader, 2), timeout=timeout)
        ver, status = struct.unpack('!BB', response)
        
        return ver == 0x01 and status == UsernamePasswordAuthStatus.SUCCESS.value
    except Exception:
        return False

def build_address_data(target_host: str):
    """构建地址数据"""
    try:
        ip_obj = ipaddress.ip_address(target_host)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return socket.inet_pton(socket.AF_INET, str(ip_obj)), SocksAddressType.IPV4
        else:
            return socket.inet_pton(socket.AF_INET6, str(ip_obj)), SocksAddressType.IPV6
    except ValueError:
        encoded = target_host.encode('utf-8')
        return struct.pack('!B', len(encoded)) + encoded, SocksAddressType.DOMAINNAME

async def skip_bind_address(reader: asyncio.StreamReader, atyp_val: int, timeout: float):
    """跳过绑定地址"""
    try:
        atyp = SocksAddressType(atyp_val)
        if atyp == SocksAddressType.IPV4:
            await asyncio.wait_for(read_exact(reader, 6), timeout=timeout)
        elif atyp == SocksAddressType.DOMAINNAME:
            domain_len = (await asyncio.wait_for(read_exact(reader, 1), timeout=timeout))[0]
            await asyncio.wait_for(read_exact(reader, domain_len + 2), timeout=timeout)
        elif atyp == SocksAddressType.IPV6:
            await asyncio.wait_for(read_exact(reader, 18), timeout=timeout)
    except Exception:
        pass

async def try_proxy_connection(target_host: str, target_port: int, proxy_config: dict, timeout: float):
    """通过代理连接"""
    if not proxy_config or not proxy_config.get('host'):
        return None, None
    
    proxy_host = proxy_config['host']
    proxy_port = proxy_config.get('port', 1080)
    use_tls = proxy_config.get('use_tls', False)
    username = proxy_config.get('username')
    password = proxy_config.get('password')
    
    try:
        # 连接到代理
        if use_tls:
            proxy_reader, proxy_writer = await create_tls_connection(proxy_host, proxy_port, timeout)
        else:
            proxy_reader, proxy_writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
            )
        
        if not proxy_writer:
            return None, None
        
        # 认证协商
        auth_methods = [SocksAuthMethod.NO_AUTHENTICATION_REQUIRED.value]
        if username and password:
            auth_methods.append(SocksAuthMethod.USERNAME_PASSWORD.value)
        
        auth_request = struct.pack('!BB', SOCKS_VERSION, len(auth_methods))
        for method in auth_methods:
            auth_request += struct.pack('!B', method)
        
        proxy_writer.write(auth_request)
        await proxy_writer.drain()
        
        # 读取认证响应
        auth_response = await asyncio.wait_for(read_exact(proxy_reader, 2), timeout=timeout)
        ver, selected_method = struct.unpack('!BB', auth_response)
        
        if ver != SOCKS_VERSION or selected_method == SocksAuthMethod.NO_ACCEPTABLE_METHODS.value:
            raise ConnectionRefusedError("代理认证失败")
        
        # 用户名密码认证
        if selected_method == SocksAuthMethod.USERNAME_PASSWORD.value:
            if not username or not password:
                raise ConnectionRefusedError("需要认证但未提供凭据")
            if not await authenticate_with_proxy(proxy_reader, proxy_writer, username, password, timeout):
                raise ConnectionRefusedError("代理认证失败")
        
        # 发送CONNECT请求
        addr_data, atyp = build_address_data(target_host)
        connect_request = struct.pack('!BBBB', SOCKS_VERSION, SocksCommand.CONNECT.value, 0x00, atyp.value)
        connect_request += addr_data + struct.pack('!H', target_port)
        
        proxy_writer.write(connect_request)
        await proxy_writer.drain()
        
        # 读取CONNECT响应
        response_header = await asyncio.wait_for(read_exact(proxy_reader, 4), timeout=timeout)
        ver, status_val, rsv, atyp_val = struct.unpack('!BBBB', response_header)
        
        if ver != SOCKS_VERSION or status_val != SocksReplyStatus.SUCCEEDED.value:
            raise ConnectionRefusedError(f"代理CONNECT失败: {status_val}")
        
        # 跳过绑定地址
        await skip_bind_address(proxy_reader, atyp_val, timeout)
        
        logger.info(f"通过{'TLS ' if use_tls else ''}代理成功连接到 {target_host}:{target_port}")
        return proxy_reader, proxy_writer
        
    except Exception as e:
        logger.warning(f"代理连接失败: {e}")
        if 'proxy_writer' in locals() and proxy_writer:
            try:
                proxy_writer.close()
                await proxy_writer.wait_closed()
            except Exception:
                pass
        return None, None

# --- 简化的UDP中继 ---
class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, client_writer):
        self.client_writer = client_writer
        self.client_udp_addr = None
        self.transport = None
        self.active = True
        self.last_activity = time.time()
    
    def connection_made(self, transport):
        self.transport = transport
        sockname = transport.get_extra_info('sockname')
        logger.info(f"UDP中继启动: {sockname}")
    
    def datagram_received(self, data, addr):
        if not self.active:
            return
        
        self.last_activity = time.time()
        
        if self.client_udp_addr == addr:
            # 来自客户端的数据
            self._handle_client_data(data, addr)
        elif self.client_udp_addr:
            # 来自目标的数据
            self._handle_target_data(data, addr)
        else:
            # 第一个数据包，建立客户端地址
            self.client_udp_addr = addr
            self._handle_client_data(data, addr)
    
    def _handle_client_data(self, data, addr):
        try:
            if len(data) < 10:
                return
            
            # 简化的SOCKS UDP解析
            rsv, frag, atyp = struct.unpack('!HBB', data[:4])
            if rsv != 0 or frag != 0:
                return
            
            offset = 4
            if atyp == SocksAddressType.IPV4.value:
                target_host = socket.inet_ntop(socket.AF_INET, data[offset:offset+4])
                offset += 4
            elif atyp == SocksAddressType.DOMAINNAME.value:
                domain_len = data[offset]
                offset += 1
                target_host = data[offset:offset+domain_len].decode('utf-8', errors='ignore')
                offset += domain_len
            else:
                return
            
            target_port = struct.unpack('!H', data[offset:offset+2])[0]
            payload = data[offset+2:]
            
            if self.transport:
                self.transport.sendto(payload, (target_host, target_port))
                
        except Exception as e:
            logger.debug(f"UDP客户端数据处理失败: {e}")
    
    def _handle_target_data(self, data, addr):
        try:
            # 构建SOCKS UDP回复
            header = b'\x00\x00\x00'  # RSV, FRAG
            
            ip_obj = ipaddress.ip_address(addr[0])
            if isinstance(ip_obj, ipaddress.IPv4Address):
                header += struct.pack('!B', SocksAddressType.IPV4.value)
                header += socket.inet_pton(socket.AF_INET, addr[0])
            else:
                header += struct.pack('!B', SocksAddressType.IPV6.value)
                header += socket.inet_pton(socket.AF_INET6, addr[0])
            
            header += struct.pack('!H', addr[1])
            
            if self.transport and self.client_udp_addr:
                self.transport.sendto(header + data, self.client_udp_addr)
                
        except Exception as e:
            logger.debug(f"UDP目标数据处理失败: {e}")
    
    def close(self):
        self.active = False
        if self.transport:
            self.transport.close()

# --- 命令处理 ---
async def handle_connect(reader, writer, client_addr, dst_atyp, dst_host, dst_port, 
                        timeout, proxy_config):
    """处理CONNECT命令"""
    logger.info(f"{client_addr}: CONNECT {dst_host}:{dst_port}")
    
    route_health = host_route_manager.get(dst_host)
    target_reader, target_writer = None, None
    connection_method = "direct"
    
    # 尝试直接连接
    if route_health.is_healthy():
        target_reader, target_writer = await try_direct_connection(dst_host, dst_port, timeout)
        
        if not target_writer:
            logger.debug(f"{client_addr}: 直连失败，尝试代理")
    
    # 尝试代理连接
    if not target_writer and proxy_config:
        target_reader, target_writer = await try_proxy_connection(
            dst_host, dst_port, proxy_config, timeout
        )
        if target_writer:
            connection_method = "proxy"
            if route_health.is_healthy():
                route_health.mark_failure()
    
    if target_writer:
        # 连接成功
        await send_socks_reply(writer, SocksReplyStatus.SUCCEEDED, dst_atyp, dst_host, dst_port)
                
        # 处理HTTPS SNI检测（简化版）
        if dst_port == 443 and connection_method == "direct":
            tls_success = False
            try:
                first_data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=2)
                if first_data:
                    target_writer.write(first_data)
                    await target_writer.drain()
                    
                    # 等待响应
                    response = await asyncio.wait_for(target_reader.read(BUFFER_SIZE), timeout=2)
                    if response:
                        writer.write(response)
                        await writer.drain()
                        tls_success = True
            except asyncio.TimeoutError:
                tls_success = True
            except Exception as e:
                logger.debug(f"TLS 错误: {e}")

            #print(f"tls_success: {tls_success}" )
            if not tls_success:
                route_health.mark_failure()
                try:
                    target_writer.close()
                except Exception:
                    pass
                
                target_reader, target_writer = await try_proxy_connection(
                    dst_host, dst_port, proxy_config, timeout
                )
                if target_writer and first_data:
                    target_writer.write(first_data)
                    await target_writer.drain()
                connection_method = "proxy"            
        
        if target_writer:
            if connection_method == "direct":
                route_health.mark_success()            
            host_route_manager.save_health_status()
            logger.info(f"{client_addr}: 通过{connection_method}连接到 {dst_host}:{dst_port}")
            
            # 开始数据转发
            task1 = asyncio.create_task(pipe_data(reader, target_writer, f"客户端({client_addr})", f"目标({dst_host}:{dst_port})"))
            task2 = asyncio.create_task(pipe_data(target_reader, writer, f"目标({dst_host}:{dst_port})", f"客户端({client_addr})", False))
            
            done, pending = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
            
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
    else:
        # 连接失败
        logger.warning(f"{client_addr}: 所有连接尝试失败 {dst_host}:{dst_port}")
        await send_socks_reply(writer, SocksReplyStatus.HOST_UNREACHABLE)
    
    # 清理
    if target_writer and not target_writer.is_closing():
        target_writer.close()
        await target_writer.wait_closed()

async def handle_udp_associate(reader, writer, client_addr, dst_host, dst_port):
    """处理UDP_ASSOCIATE命令"""
    logger.info(f"{client_addr}: UDP_ASSOCIATE {dst_host}:{dst_port}")
    
    try:
        # 获取服务器地址
        server_addr = writer.get_extra_info('sockname')
        if not server_addr:
            await send_socks_reply(writer, SocksReplyStatus.GENERAL_SOCKS_SERVER_FAILURE)
            return
        
        # 创建UDP中继
        loop = asyncio.get_running_loop()
        udp_relay = UDPRelay(writer)
        
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: udp_relay, local_addr=(server_addr[0], 0)
        )
        
        relay_addr = transport.get_extra_info('sockname')
        
        # 发送成功回复
        relay_ip_obj = ipaddress.ip_address(relay_addr[0])
        if isinstance(relay_ip_obj, ipaddress.IPv4Address):
            atyp = SocksAddressType.IPV4
        else:
            atyp = SocksAddressType.IPV6
            
        await send_socks_reply(writer, SocksReplyStatus.SUCCEEDED, atyp, relay_addr[0], relay_addr[1])
        
        # 监控TCP连接和UDP活动
        while udp_relay.active and not reader.at_eof():
            if time.time() - udp_relay.last_activity > DEFAULT_UDP_TIMEOUT:
                logger.info(f"{client_addr}: UDP中继超时")
                break
            await asyncio.sleep(1)
        
        udp_relay.close()
        
    except Exception as e:
        logger.error(f"{client_addr}: UDP_ASSOCIATE错误 - {e}")
        await send_socks_reply(writer, SocksReplyStatus.GENERAL_SOCKS_SERVER_FAILURE)

# --- 主处理函数 ---
async def handle_client(reader, writer, proxy_config, timeout):
    """处理客户端连接"""
    client_addr = writer.get_extra_info('peername')
    client_addr_str = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "未知"
    
    #logger.info(f"接受连接: {client_addr_str}")
    
    try:
        # 1. 认证
        if not await handle_socks_authentication(reader, writer, client_addr_str):
            logger.warning(f"{client_addr_str}: 认证失败")
            return
        
        # 2. 读取请求
        request_header = await read_exact(reader, 3)
        ver, cmd_val, rsv = struct.unpack('!BBB', request_header)
        
        if ver != SOCKS_VERSION or rsv != 0x00:
            await send_socks_reply(writer, SocksReplyStatus.GENERAL_SOCKS_SERVER_FAILURE)
            return
        
        try:
            cmd = SocksCommand(cmd_val)
        except ValueError:
            await send_socks_reply(writer, SocksReplyStatus.COMMAND_NOT_SUPPORTED)
            return
        
        # 3. 解析地址
        dst_atyp, dst_host, dst_port = await parse_socks_address_port(reader, client_addr_str)
        if not dst_atyp or not dst_host or dst_port is None:
            await send_socks_reply(writer, SocksReplyStatus.ADDRESS_TYPE_NOT_SUPPORTED)
            return
        
        # 4. 处理命令
        if cmd == SocksCommand.CONNECT:
            await handle_connect(reader, writer, client_addr_str, dst_atyp, dst_host, dst_port, timeout, proxy_config)
        elif cmd == SocksCommand.UDP_ASSOCIATE:
            await handle_udp_associate(reader, writer, client_addr_str, dst_host, dst_port)
        else:
            await send_socks_reply(writer, SocksReplyStatus.COMMAND_NOT_SUPPORTED)
            
    except Exception as e:
        logger.error(f"{client_addr_str}: 处理错误 - {e}", exc_info=True)
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

# --- 服务器主函数 ---
async def start_server(host, port, timeout, proxy_url):
    """启动SOCKS5服务器"""
    proxy_config = parse_proxy_url(proxy_url) if proxy_url else {}
    
    if proxy_config and proxy_config.get('host'):
        tls_info = "TLS " if proxy_config.get('use_tls') else ""
        auth_info = "带认证 " if proxy_config.get('username') else ""
        logger.info(f"上游代理: {tls_info}{auth_info}{proxy_config['host']}:{proxy_config['port']}")
    
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, proxy_config, timeout),
        host, port
    )
    
    addr = server.sockets[0].getsockname()
    logger.info(f"SOCKS5服务器启动: {addr[0]}:{addr[1]}")
    
    if ENABLE_USERNAME_PASSWORD_AUTH:
        logger.info(f"用户认证: 已启用 ({len(VALID_CREDENTIALS)} 个用户)")
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="简化的SOCKS5代理服务器")
    parser.add_argument('--host', default='127.0.0.1', help="监听地址")
    parser.add_argument('--port', type=int, default=8888, help="监听端口")
    parser.add_argument('--timeout', type=float, default=DEFAULT_CONNECT_TIMEOUT, help="连接超时")
    parser.add_argument('--proxy',default="socks5://127.0.0.1:8889", help="上游代理 (格式: socks5://[user:pass@]host:port)")
    parser.add_argument('--auth', help="本地认证 (格式: user1:pass1,user2:pass2)")
    parser.add_argument('--debug', action='store_true', help="调试模式")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    
    if args.auth:
        ENABLE_USERNAME_PASSWORD_AUTH = True
        for cred in args.auth.split(','):
            if ':' in cred:
                username, password = cred.split(':', 1)
                VALID_CREDENTIALS[username.strip()] = password.strip()
        logger.info(f"配置了 {len(VALID_CREDENTIALS)} 个用户")
    
    try:
        asyncio.run(start_server(args.host, args.port, args.timeout, args.proxy))
    except KeyboardInterrupt:
        logger.info("服务器关闭")
    except Exception as e:
        logger.critical(f"服务器错误: {e}") 
