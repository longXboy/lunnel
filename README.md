# Lunnel
Lunnel是一款简单易用的内网NAT穿越、反向代理软件，支持http、https、udp、tcp、unix等协议。

## 特点

1.隧道连接默认使用TCP、KCP自动切换模式,隧道传输协议可以任意替换。

2.支持AES、TLS加密，客户端与服务器端建立隧道只需一次密钥交换握手，建立连接速度更快。

3.高性能隧道连接池，保证高并发下的访问通畅。

## 快速开始

### 代理2048小程序
1.启动2048服务端，并运行在32768端口

2.修改客户端配置:

  ```server_addr: "example.com:8080"
  tunnels: 
    2048: 
      proto: "http"
      local: "http://127.0.0.1:32768"
      http_rewrite: true
  tls: 
    trusted_cert: "./cacert-example.pem"
	server_name:  "example.com"
  ```

3.修改服务端配置:
  ```server_domain: "example.com"
  port: 8080
  aes:
    secret_key: "password"
  tls:
    cert: "./example.crt"
    key: "./example.key"
  ```

4.在内网中启动客户端:
   `./lunnelCli -c ./config.yml`

5.在外网中启动服务端:
   `sudo ./lunnelSer -c ./config.yml`

## TODO

1.优化隧道连接池算法

2.底层传输协议支持QUIC