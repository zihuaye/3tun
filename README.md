# 3tun

Base on vtun-3.0.2, has following enhancements:

- TCP_NODELAY(negative Nagle's Algorithm) configurable.
  
  (default:TCP_NODELAY=0)
- TCP_CORK mode support.
  
  (default:TCP_CORK=0)
- Packet merge mode, can merge 2 or 3 pkt in one crypting frame. It can improve performance of tunnels with hw crypto devices that perform better in large frame encrypt/decrypting.

  (default: merge 2)(option: -a off -b merge 3)
- GCC cross compile arm/mips/x86_64 compatible.
  
  (`#if defined(__mips__) ...  #endif`) (`__arm__ __x86_64__`)
- Legacy packet format(vtun-3.0.2) compatible.
