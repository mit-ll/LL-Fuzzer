"""
    Fuzzing template for random data

    (c) 2015 Massachusetts Institute of Technology
"""
# define grammar for NDEF Record
s_initialize("NDEF Random")
        
s_byte(0xd1, format="binary", name="header", full_range=False, fuzzable=True)
s_byte(0xd1, format="binary", name="data", full_range=True, fuzzable=True)

self.add_protocol_struct("NDEF Random")
