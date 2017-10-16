# r2scapy - a radare2 plugin that decodes packets with Scapy

[![Twitter Follow](https://img.shields.io/twitter/follow/guedou.svg?style=social)](https://twitter.com/intent/follow?screen_name=guedou)

`r2scapy` is a Python based [radare2](https://github.com/radare/radare2) plugin that decodes data as [Scapy](https://github.com/secdv/scapy/) packets. It is useful to quickly verify that a memory structure is a valid network packet!

## Example

The following example show how to decode 48 bytes of memory as a DNS packet:
```
$ git clone https://github.com/guedou/r2scapy/
$ r2 -i r2scapy.py dump.bin
 -- Execute a command on the visual prompt with cmd.vprompt
[0x00000000]> scapy DNS 0x81de3c 48
DNS(aa=1L, qr=1L, an=DNSRR(rclass=32769, ttl=120, rrname='flashair.local.', rdata='192.168.0.1', type=1), ad=0L, nscount=0, qdcount=1, ns=None, tc=0L, rd=1L, arcount=0, ar=None, opcode=0L, ra=0L, cd=0L, z=0L, rcode=0L, id=0, ancount=1, qd=DNSQR(qclass=32769, qtype=255, qname='flashair.local.'))
```

## Prerequisites

`r2scapy` requires the `r2lang`, `r2pipe` (see [r2pm](https://github.com/radare/radare2-pm) and [Scapy](http://scapy.readthedocs.io/en/latest/installation.html) Python modules.
