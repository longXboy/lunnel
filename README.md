# Lunnel
Lunnel是一款简单易用的内网NAT穿越、反向代理软件，支持http、https、udp、tcp、unix socket等协议。

## Feature

1.隧道连接默认使用TCP、KCP自动切换模式,隧道传输协议可以任意替换。

2.支持AES、TLS加密，客户端与服务器端建立隧道只需一次密钥交换握手，建立连接速度更快。

3.自建隧道连接池，保证高并发下的访问通畅。

## QuickStart

### 为docker daemon配置http api访问
1.修改服务端配置
  ```
  server_domain: example.com
  port: 8080
  aes:
    secret_key: password
  tls:
    cert: ./example.crt
    key: ./example.key
  ```
2.在启动服务端程序:
   `sudo ./lunnelSer -c ./config.yml`

3.修改客户端配置并保存:
  ```
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

4.在本地启动客户端程序:
   `./lunnelCli -c ./config.yml`

5.在浏览器中访问docker.example.com即可通过http api来控制docker

### 为2048小程序反向代理
1.使用上一例中服务端的配置并启动服务端程序:
   `sudo ./lunnelSer -c ./config.yml`

2.使用docker启动2048程序，并运行在本地32768端口：`docker run -d -p 32768:80 daocloud.io/sakeven/2048`
  
3.修改客户端配置并保存:

  ```
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

4.在本地启动客户端程序:
   `./lunnelCli -c ./config.yml`

5.通过观察客户端日志，找到外网公开访问地址后在浏览器中访问（因为本例没有为该代理隧道指定host，所以由服务端分配远程公开访问地址）

## Q&A

> **Q: 在示例配置中客户端使用的是tls加密方式，需要CA签发的SSL证书，如果没有的话怎么办?**        
> **A: 可以使用openssl自签名证书，请参考：** 
> **[基于OpenSSL自建CA和颁发SSL证书](http://seanlook.com/2015/01/18/openssl-self-sign-ca/)、[openssl生成ssl证书 ](http://blog.sina.com.cn/s/blog_4fd50c390101891c.html)**
> <br>**或者您也可以在客户端以及服务端配置文件中指定aes.secret_key从而使用aes加密**

> **Q:启动程序的时候为何报错found character that cannot start any token？**
> <br>**A: YAML格式的配置文件每一行的开头不允许出现tab字符，请将所有的tab换成空格：** 

## 完整配置说明
* [客户端配置](https://github.com/longXboy/lunnel/blob/master/cmd/lunnelCli/config-full-example.yml)

* [服务端配置](https://github.com/longXboy/lunnel/blob/master/cmd/lunnelSer/config-full-example.yml)

## TODO
- [x] 持久化客户端获得的远公开访问地址，不再因为暂时失联而重新分配公开访问地址

- [x] 使用http api实时修改客户端的代理隧道支持，不需要重启客户端

- [ ] 优化隧道连接池算法

- [ ] 底层传输协议支持QUIC

- [ ] 提供dashboard管理界面，开放http接口

