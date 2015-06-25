"""
    This our general fuzzer framework

    (c) 2015 Massachusetts Institute of Technology
"""

# Native
import multiprocessing
import os
import time
import datetime
import re

import logging
log = logging.getLogger(__name__)

# 3rd Party
from nfc.ndef.error import *
from nfc.dev.pn53x import FrameError


# LL RFID Library
import llfuzzer.globals as G

class InputGenerator:
    """
        Abstract class for our fuzzing input generation
    """
    def __init__(self):
        pass

    def get_next_input(self):
        print "Implemented by inheriting class."

    def close(self):
        print "Implemented by inheriting class."



class InputGeneratorFile(InputGenerator):
    """
        Read in inputs verbatim from a file on disk
    """

    def __init__(self, filename):
        """
            Initialize our file reader input

        :param filename: Filename of input containing 1 fuzzed input per line
        :return:
        """
        if not os.path.exists(filename):
            log.error("Fuzzer input file does not exist.")
            self.filename
            self.f = None
            return

        # Open our file
        self.filename = filename
        self.f = open(filename, "r")

    def next(self):
        """
            Return the next input that is to be fuzzed
        """
        # File closed?
        if self.f.closed:
            return None

        # Read and return the next line
        line = self.f.readline()
        if line == "":
            self.close()
            return None
        else:
            # Trim the suffix added by our generator
            return line[:-3]

    def close(self):
        """
            Close up shop
        """
        if not self.f.closed:
            self.f.close()

class Fuzzer:
    """
           Just a place holder for now.
    """
    def __init__(self):
        pass

class NDEFFuzzer(Fuzzer, multiprocessing.Process):
    """
        Class to handle all of our NDEF fuzzing
    """

    def __init__(self, reader, fuzz_device, sleep_time=2,
                 check_comm=True,
                 enforce_comm=True,
                 reset_radio=False):
        """
            Initialize our fuzzer with a reader, device to fuzz,
            and input generator

        :param reader: Reader object that will send commands to our device
        :param fuzz_device: Interface to the device that is being fuzzed (adb)
        :param sleep_time: How much time to sleep between inputs
        :param check_comm: True/False to check communication before every input
        :param enforce_comm: Ensure that our communication channel is active
        before continuing to fuzz the device
        :param reset_radio: True/False Should we reset the radio between
        trials? (Requires root)
        :return:
        """

        multiprocessing.Process.__init__(self)

        # Just save our objects
        self.reader = reader
        self.device = fuzz_device

        # Init our trials to 0
        self.trial_num = 0

        self.output_dir = None

        # time to sleep between fuzzes
        self.sleep_time = sleep_time

        # Reset radio between trials?
        self.reset_radio = reset_radio

        # Are we confirming valid communication?
        self.enforce_comm = enforce_comm
        if enforce_comm:
            self.check_comm = True
        else:
            self.check_comm = check_comm

    def _nfc_test_comm(self):
        """
            This will send known good NFC tag and ensure that we get the
            expected response
        """
        log.info("Testing NFC communication....")
        # Read known good file
        f = open(G.NFC_TAG_GOOD, "r")
        good_data = f.read()
        f.close()

        logger = self.device.get_logger()

        logger.start()

        self.reader.ndef_push(good_data)

        time.sleep(2)

        log_output = logger.stop()

        for good_output in G.NFC_TAG_GOOD_OUTPUT:
            m = re.search(good_output, log_output, re.DOTALL)

            if m is not None:
                return True
        
        # Failed communication?
        self._log("NFC Communication failure. (See Below)")
        self._log("---")
        self._log(G.NFC_TAG_GOOD_OUTPUT)
        self._log("---")
        self._log(log_output)
        self._log("---")
        
        return False

    def _setup_communication(self):
        """
            This will make sure that the reader and device are communicating
            properly
        """
        attempts = 0
        # Loop until we get communication back
        try:
            while not self._nfc_test_comm():

                if not self.enforce_comm:
                    return

                if attempts < G.NFC_RESET_ATTEMPTS:
                    if self.device.HAS_ROOT:
                        self._log("Trying nfc reset.")
                        self.device.nfc_reset()
                        time.sleep(G.NFC_RESET_TIME)
                    else:
                        self._log("Trying a simple sleep")
                        time.sleep(G.NFC_RESET_TIME)
                else:
                    self._log("Trying device reboot.")
                    self.device.reboot()

                    # restart our log
                    self.device_log.stop()
                    self.device_log = self.device.get_logger(os.path.join(
                        self.output_dir, G.LOGFILE_DEVICE))
                    self.device_log.start(clearFirst=False)

                attempts += 1
        except:
            self._log("ERROR: Reader Communication failed!  ")
            import traceback
            traceback.print_exc()

        return True

    def _write_to_file(self, filename, data):
        f = open(filename, "w+")
        f.write(data)
        f.close()

    def _log(self, message):
        """
            Nice function to write logs while fuzzing for later inspection
        """
        timestamp = str(datetime.datetime.now())

        if self.output_dir is not None:
            filename = os.path.join(self.output_dir, G.LOGFILE_FUZZER)
            fuzz_log = open(filename, "a+")

            log_msg = "[%d/%s]: %s\n" % (self.trial_num, timestamp, message)

            fuzz_log.write(log_msg)
            fuzz_log.close()

        log.info(message)

    def fuzz(self, fuzzer_input, log_dir, reboot_first=True, check_comm=True):
        """
            Start fuzzing our device with the provided input

        :param fuzzer_input: Generator to provide inputs to fuzz
        :param log_dir: Directory to log our results to
        :param reboot_first: Should we reboot the device first to have a
        fresh start?
        :param check_comm: True/False Check the communication after every trial?
        :return:
        """

        output_dir = os.path.join(G.OUTPUT_DIR, log_dir)
        # Create our output directory
        if os.path.exists(output_dir):
            log.error("%s already exist!" % output_dir)
            return False

        log.info("Creating directory %s" % output_dir)
        
        os.makedirs(output_dir)

        self.output_dir = output_dir

        # Reboot our device
        # TODO: Add commandline flag?
        self._log("Rebooting device.")
        if reboot_first:
            self.device.reboot()

        # Save our startup log data
        #
        # TODO: Figure out how to do this.
        #

        self.device_log = self.device.get_logger(os.path.join(
            self.output_dir,  G.LOGFILE_DEVICE))
        self.device_log.start(clearFirst=False)

        # Loop over all of the inputs that our generator gives us
        self.trial_num = 0

        self._log("Starting fuzzing.")
        for fuzz_input in fuzzer_input:

            self._log("Starting trial %d." % self.trial_num)

            # setup our directories
            trial_path = os.path.join(output_dir, "trial_%05d" % self.trial_num)
            os.makedirs(trial_path)
            phone_log = os.path.join(trial_path, "device.log")
            input_filename = os.path.join(trial_path, "input.bin")
            problem_filename = os.path.join(trial_path, "problem.log")

            # write the input used to a file
            self._write_to_file(input_filename, fuzz_input)

            # Should we reset the radio every time?
            if self.reset_radio:
                self.device.reset_nfc()

            # Start Logging
            instance_log = self.device.get_logger(phone_log)
            instance_log.start()

            # Send NDEF data
            try:
                log.info("Sending NDEF data...")

                for i in range(G.CHECK_VERSION_RETRIES):
                    # Start logging
                    tmp_log = self.device.get_logger()
                    tmp_log.start()

                    # Send our fuzzed input
                    self.reader.ndef_push(fuzz_input, send_raw=True)
                    time.sleep(1)

                    # Stop logging
                    tmp_log_str = tmp_log.stop()

                    # Ensure that the device actually read it
                    m = re.search(G.NFC_BAD_VERSION, tmp_log_str, re.DOTALL)
                    if m is None or G.CHECK_VERSION is False:
                        break

                    self._log("Got bad version, trying again.")

            except LengthError:
                error = "Bad length with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except FormatError:
                error = "Bad format with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except EncodeError, DecodeError:
                error = "Encoding/Decoding issues with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except FrameError:
                error = "pn532x did not respond!"
                self._write_to_file(problem_filename, error)
                log.error(error)

            # Sleep a bit
            time.sleep(self.sleep_time)

            # Test with good input
            if check_comm:
                log.info("Checking Communication...")
                self._setup_communication()

            # Sleep a bit
            time.sleep(self.sleep_time)

            # stop logging and continue
            instance_log.stop()

            self._log("Trial finished.")

            # get ready for the next trial
            self.trial_num += 1

        self.device_log.stop()

        self._log("Fuzzing complete. Closing reader.")

        return True

    def refuzz(self, fuzz_input, output_dir, num_trials, reboot_first=True,
               check_comm=True):
        """
            Take in previous inputs that may have caused crashes and try them
            again

        :param fuzz_input: Raw input to send
        :param output_dir: Directory to store output of fuzz
        :param num_trials: Number of times to send the given input
        :param reboot_first: True/False Should we reboot for a clean slate?
        :param check_comm: True/False Check the communication channel after
        each trial?
        :return:
        """

        # Create our output directory
        if not os.path.exists(output_dir):
            log.error("%s does not exist!" % output_dir)
            return False

        self.output_dir = output_dir

        # Reboot our device
        # TODO: Add commandline flag?
        self._log("Rebooting device.")
        if reboot_first:
            self.device.reboot()

        # Save our startup log data
        #
        # TODO: Figure out how to do this.
        #

        self._log("Starting fuzzing.")

        for i in range(num_trials):

            self._log("Starting trial %d" % i)

            # setup our directories
            phone_log = os.path.join(output_dir, "refuzz_device_%d.log"%i)
            problem_filename = os.path.join(output_dir, "refuzz_problem_%d.log"%i)

            # Should we reset the radio every time?
            if self.reset_radio:
                self.device.reset_nfc()

            # Start Logging
            instance_log = self.device.get_logger(phone_log)
            instance_log.start()

            # Send NDEF data
            try:
                log.info("Sending NDEF data...")
                
                # Send our ndef package
                self.reader.ndef_push(fuzz_input, send_raw=True)

            except LengthError:
                error = "Bad length with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except FormatError:
                error = "Bad format with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except EncodeError, DecodeError:
                error = "Encoding/Decoding issues with the fuzzing input, skipping!"
                self._write_to_file(problem_filename, error)
                log.error(error)
            except FrameError:
                error = "pn532x did not respond!"
                self._write_to_file(problem_filename, error)
                log.error(error)

            # Sleep a bit
            time.sleep(self.sleep_time)

            # Test with good input
            if check_comm:
                log.info("Checking Communication...")
                self._setup_communication()

            # Sleep a bit
            time.sleep(self.sleep_time)

            # stop logging and continue
            instance_log.stop()

            self._log("Trial %d finished." % i)

        self._log("Refuzzing complete. Closing reader.")

        return True

