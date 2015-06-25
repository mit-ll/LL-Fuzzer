"""
    Fuzzing template for Raw Packets

    (c) 2015 Massachusetts Institute of Technology
"""
# define grammar for LLCP Raw Packet
# Later we will have LLCP packets with well formed headers
s_initialize("LLCP Raw Small")
        
# LLCP header

# DSAP - destination address - 6 bits
# This will be automatically inserted by llcp_client.send_llcp()

# PTYPE - payload type - 4 bits
#        UI (Unnumbered info - send data w/o connect) - 0011
#		CONNECT - 0100
#		DISC - 0101
#		I - 1100 (send data across link connection) uses seq numbers
#		RNR (receive not ready)
#		SNL (service name lookup) - find services - 1001

# SSAP - source address - 6 bits

# Sequence number - 8 bits (if used)

# 8 bytes at a time, max MIU for Nexus 4 seems to be 248 bytes
s_double(0x4141414141414141, format="binary", fuzzable=True)
s_double(0x4141414141414141, format="binary", fuzzable=True)

self.add_protocol_struct("LLCP Raw Small")
