English | [中文](README.md)


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
