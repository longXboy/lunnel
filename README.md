中文 | [English](README_en.md)

# Lunnel
lunnel 是一款简单易用的内网NAT穿越、反向代理软件，支持 HTTP, HTTPS, UDP, TCP、Unix socket 协议。

## Feature

1. 隧道连接默认使用 TCP、KCP 自动切换模式，隧道传输协议可以任意替换。
2. 支持 AES、TLS 加密，客户端与服务器端建立隧道只需一次密钥交换握手，建立连接速度更快。
3. 自建隧道连接池，保证高并发下的访问通畅。
4. 单个连接支持多路并发(类似http 2.0)，更节省资源。

## QuickStart

### 为 docker daemon 配置 HTTP API 访问

1. 修改服务端配置：

```yaml
server_domain: example.com
port: 8080
aes:
  secret_key: password
tls:
  cert: ./example.crt
  key: ./example.key
```

2. 在公网启动服务端程序：`sudo ./lunnelSer -c ./config.yml`
3. 修改客户端配置并保存：

```yaml
server_addr: <your_server_ip>:8080
tunnels:
  docker:
    schema: http
    local: unix:///var/run/docker.sock
    host: docker.exmpale.com
aes:
  secret_key: password
enable_compress: true
```

4. 在本地启动客户端程序：`./lunnelCli -c ./config.yml`
5. 在浏览器中访问 docker.example.com 即可通过 http api 来控制 docker

### 为 2048 小程序反向代理

1. 使用上一例中服务端的配置并启动服务端程序：`sudo ./lunnelSer -c ./config.yml`
2. 使用 docker 启动 2048 程序，并运行在本地 32768 端口：`docker run -d -p 32768:80 daocloud.io/sakeven/2048`
3. 修改客户端配置并保存：

```yaml
server_addr: <your_server_ip>:8080
tunnels:
  2048:
    schema: http
    local: http://127.0.0.1:32768
    http_host_rewrite: www.2408.com
tls:
  trusted_cert: ./cacert-example.pem
server_name:  example.com
```

4. 在本地启动客户端程序：`./lunnelCli -c ./config.yml`
5. 通过观察客户端日志，找到外网公开访问地址后在浏览器中访问（因为本例没有为该代理隧道指定 host，所以由服务端分配远程公开访问地址）

## Q&A

> **Q: 在示例配置中客户端使用的是 TLS 加密方式，需要 CA 签发的 SSL 证书，如果没有的话怎么办?**
> <br>**A: 可以使用 OpenSSL 自签名证书，请参考：[基于 OpenSSL 自建 CA 和颁发 SSL 证书](http://seanlook.com/2015/01/18/openssl-self-sign-ca/)、[OpenSSL 生成 SSL 证书](http://blog.sina.com.cn/s/blog_4fd50c390101891c.html)；<br>或者您也可以在客户端以及服务端配置文件中指定 `aes.secret_key` 从而使用 aes 加密。**

> **Q: 启动程序的时候为何报错 `found character that cannot start any token`？**
> <br>**A: YAML 格式的配置文件每一行的开头不允许出现 tab 字符，请将所有的 tab 换成空格。**

## Config Reference

- [客户端配置说明](https://github.com/longXboy/lunnel/blob/master/cmd/lunnelCli/config-full-example.yml)
- [服务端配置说明](https://github.com/longXboy/lunnel/blob/master/cmd/lunnelSer/config-full-example.yml)

## TODO

- [x] 持久化客户端获得的远公开访问地址，不再因为暂时失联而重新分配公开访问地址
- [x] 使用 HTTP API 实时修改客户端的代理隧道支持，不需要重启客户端
- [ ] 优化隧道连接池算法
- [ ] 底层传输协议支持 QUIC
- [ ] 提供 Dashboard 管理界面，开放 HTTP 接口
- [ ] 集成raft一致性协议，服务端可横向伸缩扩展

</details>
