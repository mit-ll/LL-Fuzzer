"""
    Fuzzing template for Unnumbered Info

    (c) 2015 Massachusetts Institute of Technology
"""
# define grammar for LLCP UI Packet
s_initialize("LLCP Unnumbered Info")
        
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

# DSAP = 16, PTYPE = 0b0011, SSAP = 32
s_byte(0x40, format="binary", fuzzable=False)
s_byte(0xe0, format="binary", fuzzable=False)

s_byte(0x41, format="binary", full_range=True, fuzzable=True)
s_byte(0x41, format="binary", fuzzable=True)

self.add_protocol_struct("LLCP Unnumbered Info")
