# SOCKS5代理服务器

这是一个简化且优化的SOCKS5代理服务器实现，支持TLS连接、用户名密码认证、UDP中继和上游代理回退等功能。  
无需手动配置不可连接网站，先尝试直接连接，如果不可连，再使用SOCKS5代理连接。  
建议非大陆网站流量都通过这个SOCKS5代理服务器。

## 主要特性

✅ **完整的SOCKS5协议支持**
- CONNECT命令（TCP代理）
- UDP_ASSOCIATE命令（UDP中继）
- IPv4、IPv6和域名地址类型

✅ **认证支持**
- 无认证模式
- 用户名密码认证（RFC 1929）
- 本地和上游代理认证

✅ **TLS支持**
- 支持通过TLS连接到上游代理
- 自动SSL上下文配置

✅ **智能连接管理**
- 直连优先，失败自动回退到代理
- 连接健康状态跟踪
- 失败冷却机制

✅ **UDP中继**
- 完整的UDP ASSOCIATE支持
- 自动地址学习和中继

## 使用方法

### 基本启动
```bash
python autosocks5 --host 0.0.0.0 --port 1080
```

### 启用用户认证
```bash
python autosocks5 --auth "admin:secret,user:pass123"
```

### 配置上游代理
```bash
# 普通SOCKS5代理
python autosocks5 --proxy "socks5://proxy.example.com:1080"

# 带TLS的代理
python autosocks5 --proxy "socks5+tls://proxy.example.com:443"

# 带认证的代理
python autosocks5 --proxy "socks5://user:pass@proxy.example.com:1080"

# TLS + 认证
python autosocks5 --proxy "socks5+tls://user:pass@secure-proxy.com:443"
```

### 完整配置示例
```bash
python autosocks5 \
  --host 0.0.0.0 \
  --port 1080 \
  --auth "admin:secret123,user:pass456" \
  --proxy "socks5+tls://proxyuser:proxypass@secure-proxy.com:443" \
  --timeout 5.0 \
  --debug
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `127.0.0.1` | 监听地址 |
| `--port` | `8888` | 监听端口 |
| `--timeout` | `2.0` | 连接超时时间（秒） |
| `--proxy` | 无 | 上游代理URL |
| `--auth` | 无 | 本地用户认证配置 |
| `--debug` | `False` | 启用调试日志 |

## 代理URL格式

支持以下URL格式：

```
socks5://host:port                           # 基本SOCKS5
socks5+tls://host:port                       # TLS SOCKS5
socks5://username:password@host:port         # 带认证的SOCKS5
socks5+tls://username:password@host:port     # TLS + 认证
```

