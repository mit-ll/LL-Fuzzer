"""
    Fuzzing template for string sizer

    (c) 2015 Massachusetts Institute of Technology
"""
# define grammar for NDEF Record
s_initialize("NDEF String Sizer")

# NDEF record header
s_byte(0xd1, format="binary", name="header", full_range=True, fuzzable=False)

# NDEF type length field, tied to 'type block'
s_size("type block", name="type length", format="binary", length=1, fuzzable=True)

# Long payload, depends on whether SR flag is set
#if s_block_start("long payload long", dep="header", dep_value=16, dep_compare="!&"):
#    s_size("payload block", format="binary", length = 4, fuzzable=False)
#s_block_end()


# Short payload, depends on whether SR flag is set
#if s_block_start("long payload small", dep="header", dep_value=16, dep_compare="&"):
#    s_size("payload block", format="binary", length = 1, fuzzable=False)
#s_block_end()

s_size("payload block", format="binary", length = 1, fuzzable=True)

# Id Length block, depends on whether IL flag is set
#if s_block_start("id length block", dep="header", dep_value=8, dep_compare="!&"):
#    s_size("id block", name="id length", format="binary", length=1, math=lambda x: x/2, fuzzable=False)
#s_block_end()

# Type block
if s_block_start("type block"):
    s_string("T", fuzzable=False)
s_block_end()


# ID block
#if s_block_start("id block", dep="header", dep_value=8, dep_compare="!&"):
#    s_string("ID!", encoding="hex", fuzzable=False)
#s_block_end()


# The payload
if s_block_start("payload block"):
    s_size("lang code", name="lang code len", format="binary", length=1, fuzzable=True)
    if s_block_start("lang code"):
        s_string("en", fuzzable=False)
    s_block_end()
    s_string("sup, ultralight?", name="text", fuzzable=True)
s_block_end()


self.add_protocol_struct("NDEF String Sizer")
