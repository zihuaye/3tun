# 3tun

Base on vtun-3.0.2, has following improvement:

- Larger tunnel MTU supported, up to 8000 bytes.

- Packet merge mode, can merge 2 or 3 pkt in one crypting frame. It can improve performance of tunnels with hw crypto devices that perform better in large frame encrypt/decrypting(like: MT7621 SoC). 

  As you know, regular packet size is about 100 - 1500 bytes.

  (default: merge 2)
  
  (option -a: off; option -b: merge 3)
- `TCP_CORK` mode support.
  
  (default:`TCP_CORK=0`)(option -c: on)
- `TCP_NODELAY`(negative Nagle's Algorithm) configurable.
  
  (default:`TCP_NODELAY=0`)(option -d: on)
- GCC cross compile `arm/mips/x86_64` compatible.
  
  (`#if defined(__mips__) ...  #endif`) (`__arm__ __x86_64__`)
- Legacy packet format(vtun-3.0.2) compatible. The tunnel peers having new/old version can talk to determine the right working mode.
- OpenSSL 1.1 and crypto engine support.(via patch)
