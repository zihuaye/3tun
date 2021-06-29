# 3tun

Base on vtun-3.0.2, has following enhancements:

- Nagle's Algorithm supported default. TCP_NODELAY configurable.
- TCP_CORK mode support.
- Packet merge mode, which can improve performance of tunnels with hw crypto devices that suport large frame encrypt/decrypt.
- GCC cross compile arm/mips/x86_64 compatible.(`#if defined(__mips__) ...  #endif`) (`__arm__ __x86_64__`)
- More coming...

Todo:

- Legacy packet format compatible.
