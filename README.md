# Lunnel
Lunnel是一款简单易用的内网NAT穿越、反向代理软件，支持http、https、udp、tcp、unix socket等协议。

## Feature

1.隧道连接默认使用TCP、KCP自动切换模式,隧道传输协议可以任意替换。

2.支持AES、TLS加密，客户端与服务器端建立隧道只需一次密钥交换握手，建立连接速度更快。

3.高性能隧道连接池，保证高并发下的访问通畅。

## QuickStart

### 为2048小程序反向代理
1.修改服务端配置:
  ```
  server_domain: example.com
  port: 8080
  aes:
    secret_key: password
  tls:
    cert: ./example.crt
    key: ./example.key
  ```

2.在外网启动服务端:
   `sudo ./lunnelSer -c ./config.yml`

3.使用docker启动2048程序，并运行在本地32768端口：`docker run -d -p 32768:80 daocloud.io/sakeven/2048`
  
4.修改客户端配置:

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

5.在本地启动客户端:
   `./lunnelCli -c ./config.yml`

6.通过观察客户端日志，找到远程的访问地址后在浏览器中访问

### 暴露docker的unix socket在外网
1.修改服务端配置，并在外网启动服务端

2.修改客户端配置:
  ```
  server_addr: <your_server_ip>:8080
  tunnels: 
    docker: 
      schema: http
      local: unix:///var/run/docker.sock
      host: docker.exmpale.com
  aes: 
    secret_key: password
  ```

3.在本地启动客户端

4.在浏览器中访问docker.example.com即可通过restful api来控制docker

## Q&A

> **Q: 在示例配置中客户端使用的是tls加密方式，需要SSL证书，如果没有的话怎么办?**        

> **A: 可以使用openssl自签名证书，请参考：** 
> **http://seanlook.com/2015/01/18/openssl-self-sign-ca/**
> **http://blog.sina.com.cn/s/blog_4fd50c390101891c.html**
> **  或者您也可以使用aes加密、或者将aes、tls字段删除从而不使用任何加密**

> **Q:有时候出现无法启动程序，并报错found character that cannot start any token？**

> **A: YAML格式的配置文件每一行的开头不允许出现tab字符，请将所有的tab换成空格：** 

> **Q:配置中的http_rewrite是什么意思？**

> **A:有一些后端服务会根据http请求header中的host字段来展现不同的网站，启用http_rewrite功能可以动态将http请求中host字段替换城客户端配置中真实连接的host地址（也就是tunnels.local的值）** 

> **Q:为什么我访问不了docker.example.com？**

> **A:请修改/etc/hosts** 

## TODO

1.优化隧道连接池算法

2.底层传输协议支持QUIC

3.提供dashboard管理界面，开放http接口

4.持久化客户端获得的远公开访问地址，不再因为暂时失联而重新分配公开访问地址

5.客户端的代理隧道支持hot reload，不需要重启客户端
