vppl7proxy
========================

## Introduction

The VPP platform is an extensible framework that provides out-of-the-box
production quality switch/router functionality. It is the open source version
of Cisco's Vector Packet Processing (VPP) technology: a high performance,
packet-processing stack that can run on commodity CPUs.

The benefits of this implementation of VPP are its high performance, proven
technology, its modularity and flexibility, and rich feature set.

For more information on VPP and its features please visit the
[FD.io website](http://fd.io/) and
[What is VPP?](https://wiki.fd.io/view/VPP/What_is_VPP%3F) pages.

vppl7proxy is a proxy project based on the VPP, which aim at getting
high performance at application layer forwarding via zero copy during the process
routines(from routines get stream payload from TCP stack to the routines put the
handled content to the TCP stack).
A simple HTTP reverse proxy is implemented at present.
It have the same configuration concept with Nginx, such as location, upstream and 
server, it can match the host in the same way as ngx, it can also match the uri against with
location configured, it can selete a real server according to the load balance method between the
configed real servers of an upstream.
## Directory layout

| Directory name                 | Description                                 |
| ------------------------------ | ------------------------------------------- |
| @ref src/vnet/http_proxy       | VPP Based HTTP reverse proxy code           |
| @ref src/vnet/ssl_proxy        | VPP Based SSL proxy code(in coding)         |
| @ref src/vnet/https_proxy      | VPP Based HTTPS proxy code(under planning)  |

## Getting started

The project base on VPP version 19.04, it's better to make the official VPP 19.04 version
run successfully to get everything needed by VPP ready, then checkout this project and do
as following steps(assume use DPDK as the network IO interface):
1. git tag -a v19.04  -m "v19.04"
2. make build
3. setup the UIO bind the NIC and give the memory used by DPDK
4. make run(or make debug)
5. configure the box with basic network configuration and HTTP configuration, listed as follow.

## Configuration example:
```
set interface  ip address GigabitEthernet2/2/0 192.168.169.135/24
set interface state GigabitEthernet2/2/0 up

htproxy reverse static lb-name  l7proxylb vs-uri tcp://192.168.169.135/80 rs-uri tcp://192.168.169.136/80

htproxy upstream add-ups  ups-name  usgr1 method wrr
htproxy upstream add-rs ups-name usgr1 rs-name  rs1  rs-uri tcp://192.168.169.136/80

htproxy location add-location  loc-name loc123  loc-uri  ^~/static/
htproxy location add-location  loc-name loc456  loc-uri  ~*\.(gif|jpg|jpeg|html)$
htproxy location add-proxy-pass  loc-name loc456  ups-name  usgr1

htproxy server add-vs vs-name vs1
htproxy server add-sn server-name  hi-myhttp.com  vs-name vs1
htproxy server add-location loc-name loc123 vs-name vs1
htproxy server add-location loc-name loc456 vs-name vs1
htproxy server attach-lb lb-name l7proxylb vs-name vs1
```
