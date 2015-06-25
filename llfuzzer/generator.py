"""
    These classes generate inputs for fuzzing

    (c) 2015 Massachusetts Institute of Technology
"""

# Native
import os
import time
import logging
logger = logging.getLogger(__name__)

# 3rd party
from sulley import *


class Connection(pgraph.edge.edge):
    """
        Class for handling connections to the pgraph
    """

    def __init__(self, src, dst, callback=None):
        super(Connection, self).__init__(src, dst)
        self.callback = callback


class Sulley_Generator(pgraph.graph):
    """
        Class for generating fuzzing test cases from Sulley.
        Hooks into Sulley's pgraph framework. 
    """

    def __init__(self, src):
        """
            Initialize our generate based on Sulley

        :param src: Sulley protocol structure source for the graph
        :return:
        """
        super(Sulley_Generator, self).__init__()
        self.root = pgraph.node()
        self.root.name = "__ROOT_NODE__"
        self.root.label = self.root.name
        self.last_recv = None
        self.add_node(self.root)

        # connect src to Sulley pgraph
        self.connect(src)

    def log(self, msg, level=1):
        """
            Log our message to stdout

        :param msg: Message to display
        :param level: Log level
        :return:
        """
        logger.log("[%s] %s" % (time.strftime("%I:%M.%S"), msg),level=level)

    def add_node(self, node):
        """
            Add a node to our protocol graph

        :param node: Node to add
        :return: New graph
        """
        node.number = len(self.nodes)
        node.id = len(self.nodes)
        if not self.nodes.has_key(node.id):
            self.nodes[node.id] = node
        return self

    def connect(self, src, dst=None, callback=None):
        """
            Connect to our pgraph

        :param src: Source
        :param dst: Desintation
        :param callback: Parsing callback
        :return:
        """
        dst = src
        src = self.root

        if not self.find_node("name", dst.name):
            self.add_node(dst)

        edge = Connection(src.id, dst.id, callback)
        self.add_edge(edge)
        return edge

    def num_mutations(self, this_node=None, path=[]):
        """
            Number of mutations

        :param this_node: Node to start frome
        :param path: Patht to take
        :return:
        """
        if not this_node:
            this_node = self.root
            self.total_num_mutations = 0
        for edge in self.edges_from(this_node.id):
            next_node = self.nodes[edge.dst]
            self.total_num_mutations += next_node.num_mutations()
            if edge.src != self.root.id:
                path.append(edge)
            self.num_mutations(next_node, path)
        if path:
            path.pop()
        return self.total_num_mutations

    def server_init(self):
        """
            Initialize our server

        :return:
        """
        self.total_mutant_index = 0
        self.total_num_mutations = self.num_mutations()

    def generate_tests_helper(self, this_node):
        """
            Generate tests based on Sulley's pgraph

        :param this_node:
        :return:
        """
        # Helps to generate the tests based on Sulley pgraph.
        # Borrowed from Charlie Miller's NFC stuff.

        # TODO: find a framework that is flexible but less messy?

        # Start mutating this node
        for edge in self.edges_from(this_node.id):
            self.fuzz_node = self.nodes[edge.dst]
            num_mutations = self.fuzz_node.num_mutations()

            current_path = " -> %s" % self.fuzz_node.name

            self.log("current fuzz path: %s" % current_path, 2)
            self.log("fuzzed %d of %d total cases" % (
            self.total_mutant_index, self.total_num_mutations), 2)

            # loop through all possible mutations of the fuzz node.
            while True:

                # check if we have exhausted all possible mutations
                if not self.fuzz_node.mutate():
                    self.log(
                        "all possible mutations for current fuzz node exhausted",
                        2)
                    break

                self.total_mutant_index += 1

                # fuzz current test case
                self.log("fuzzing %d of %d" % (
                self.fuzz_node.mutant_index, num_mutations), 2)

                output = self.fuzz_node.render()
                yield self.print_case(self.fuzz_node, output)

            temp = self.nodes[edge.dst]
            self.generate_tests_helper(self.fuzz_node)
            temp.reset()

    def print_case(self, this_node=None, output=""):
        """
            Prints test case to file_handle
        """
        original_output = output

        if (len(self.edges_from(this_node.id)) > 0):
            for edge in self.edges_from(this_node.id):
                output = original_output
                output += self.nodes[edge.dst].render()
                self.print_case(self.nodes[edge.dst], output, file_handle)
        else:
            # return binascii.hexlify(output)
            return output

    def generate_tests(self):
        """
            Generates test cases given a Sulley pgraph node
            and prints them to file specified by filename
            or prints them to the commandline if no filename
            is provided.

            Returns a generator of test inputs.
        """

        self.server_init()
        return self.generate_tests_helper(self.root)


class Fuzz_Generator(object):
    """
        Class for generating different types of Sulley fuzz
        cases based on defined protocol structures, e.g. types of
        NDEF records.  Each case is associated with a separate
        Sulley_Generator object.
    """

    def __init__(self):
        """
            Initialize with an empty set of protocol structures

        :return:
        """
        self.protocol_structs = set()

    def add_protocol_struct(self, protocol_struct):
        """
            Adds protocol_struct (string) to list of protocol structs

        :param protocol_struct: Protocol structure to add to list
        :return:
        """
        self.protocol_structs.add(protocol_struct)

    def read_config_file(self, filename):
        """
            Read in our protocol definition from a file

        :param filename: Filename with our generator config
        :return:
        """
        logger.info("Reading config file: ", filename)

        # execute file
        execfile(filename)

        logger.info("Done.")

    def read_config_dir(self, directory_path):
        """
            Read in multiple configurations from a directory

        :param directory_path: Directory containing fuzzer configuration files
        :return:
        """
        # get all files in specified directory
        file_list = filter(lambda f: not os.path.isdir(f),
                           os.listdir(directory_path))

        for f in file_list:
            self.read_config_file(os.path.join(directory_path, f))

    def generate(self):
        """
            Generates test cases for all known Sulley input types stored
            in self.protocol_structs.  This is a generator that returns
            a bunch of generators.

            :return: Generator that produces all of the requested inputs
        """

        for p_struct_name in self.protocol_structs:
            logger.info("Generating test cases for protocol structure "
                        "'%s'." % p_struct_name)

            # Create Sulley_Generator Object
            gen = Sulley_Generator(s_get(p_struct_name))

            yield gen.generate_tests()
