<details>
<summary>English</summary>

# Lunnel
Lunnel is an easy to use intranet NAT traversal, reverse proxy software, support HTTP, HTTPS, UDP, TCP, Unix socket protocol.

## Feature

1. Tunnel connection using TCP, KCP automatic switching mode, the tunnel transmission protocol can be replaced.
2. Support AES, TLS encryption, the client and the server to establish a tunnel only a key exchange handshake, the establishment of faster connection.
3. Self-built tunnel connection pool, to ensure high access under the smooth access.
4. Single connection support multi-channel (similar to http 2.0), more resources.

## QuickStart

### Configure HTTP API access for docker daemon

1. Modify the server configuration:

`` `Yaml
Server_domain: example.com
Port: 8080
Aes
  Secret_key: password
Tls:
  Cert: ./example.crt
  Key: ./example.key
`` ``

2. Start the server program on the public network: `sudo ./lunnelSer -c. / Config.yml`
3. Modify the client configuration and save:

`` `Yaml
Server_addr: <your_server_ip>: 8080
Tunnels
  Docker
    Schema: http
    Local: unix: ///var/run/docker.sock
    Host: docker.exmpale.com
Aes
  Secret_key: password
Enable_compress: true
`` ``

4. Start the client program locally: `./lunnelCli -c. / Config.yml`
5. Access docker.example.com in the browser to control the docker via http api

### Reverse proxy for 2048 applet

1. Use the configuration of the server in the previous example and start the server program: `sudo ./lunnelSer -c. / Config.yml`
2. Use the docker to start the 2048 program and run the local 32768 port: `docker run -d -p 32768: 80 daocloud.io / sakeven / 2048`
3. Modify the client configuration and save:

`` `Yaml
Server_addr: <your_server_ip>: 8080
Tunnels
  2048:
    Schema: http
    Local: http://127.0.0.1:32768
    Http_host_rewrite: www.2408.com
Tls:
  Trusted_cert: ./cacert-example.pem
Server_name: example.com
`` ``

4. Start the client program locally: `./lunnelCli -c. / Config.yml`
5. By observing the client log, find the external network to access the address after the visit in the browser (because this example does not specify the host for the host tunnel, so the remote distribution by the server to access the address)

## Q & A

> ** Q: In the example configuration, the client uses the TLS encryption method, which requires the SSL certificate issued by the CA. What if it does not?
> A: You can use OpenSSL self-signed certificate, please refer to: [based on OpenSSL self-built CA and issued SSL certificate] (http://seanlook.com/2015/01/18/openssl-self-sign- Ca.), [OpenSSL generates SSL certificate] (http://blog.sina.com.cn/s/blog_4fd50c390101891c.html); | or you can also specify `aes' in the client and server configuration files. Secret_key` to use aes encryption. **

> ** Q: why start the procedure when the error `found character that can not start any token`? **
> A: YAML format of the configuration file at the beginning of each line does not allow tab characters, please replace all the tabs into spaces. **

## Config Reference

- [Client configuration instructions] (https://github.com/longXboy/lunnel/blob/master/cmd/lunnelCli/config-full-example.yml)
- [server configuration instructions] (https://github.com/longXboy/lunnel/blob/master/cmd/lunnelSer/config-full-example.yml)

## TODO

- [x] The remote public access address obtained by the persistent client no longer reallocates the public access address because of a temporary loss
- [x] Use the HTTP API to modify the client's proxy tunnel support in real time without restarting the client
- [ ] Optimize the tunnel connection pool algorithm
- [ ] The underlying transport protocol supports QUIC
- [ ] provides the Dashboard management interface, open the HTTP interface
- [ ] integrated raft consistency agreement, the server can be horizontal expansion and expansion

</details>

<details>
<summary>中文 (Chinese)</summary>

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
