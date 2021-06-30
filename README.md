# 3tun

Base on vtun-3.0.2, has following enhancements:

- TCP_NODELAY(negative Nagle's Algorithm) configurable.
  
  (default:TCP_NODELAY=0)
- TCP_CORK mode support.
  
  (default:TCP_CORK=0)
- Packet merge mode, which can improve performance of tunnels with hw crypto devices that suport large frame encrypt/decrypt.
- GCC cross compile arm/mips/x86_64 compatible.
  
  (`#if defined(__mips__) ...  #endif`) (`__arm__ __x86_64__`)
- More coming...

Todo:

- legacy packet format compatible.
- writev() sending multi pkts at one time.
