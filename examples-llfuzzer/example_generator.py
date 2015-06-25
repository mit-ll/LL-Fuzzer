#!/usr/bin/python
"""

    This is a sample application to demonstrate some of the uses of the 
    LL-Fuzzer Library.
    
    (c) 2015 Massachusetts Institute of Technology
"""
# LL-Fuzzer
from llfuzzer import generator

g = generator.Fuzz_Generator()
g.read_config_dir("fuzz-configs/llcp")
generators = g.generate()

for gen in generators:
    print gen.next()
    print gen.next()
    print gen.next()
    print gen.next()
    print gen.next()


