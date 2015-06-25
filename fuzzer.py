"""
    LL RFID Fuzzer
    
    Takes fuzzing input and will fuzz the phone according to the configuration.

    (c) 2015 Massachusetts Institute of Technology
"""

# Native
import optparse
import os
import logging
log = logging.getLogger(__name__)

# LL RFID Library
import llfuzzer.globals as G
import llfuzzer.fuzzer as fuzzer
import llfuzzer.rfidreader as rfidreader
import llfuzzer.rfiddevice as rfiddevice
from llfuzzer.generator import Fuzz_Generator

def main(args=None):
    """
        Consume our user inputs and start fuzzing appropriately
    """

    opts = optparse.OptionParser()

    # Phone Serial
    opts.add_option("-s", "--serial", action="store", type="string",
        dest="adb_serial", default=None,
        help="Serial of the android device to fuzz. (output from 'adb devices')")

    # Reader
    opts.add_option("-r", "--reader", action="store", type="string",
        dest="reader", default="",
        help="Address of reader. (Ex. tty:usb:0)")

    # Fuzz config file
    opts.add_option("-i", "--fuzzfile", action="store", type="string",
        dest="fuzzfile", default=None,
        help="Binary input file with 1 fuzz input per line.")

    # Fuzz input directory
    opts.add_option("-D", "--fuzzdir", action="store", type="string",
        dest="fuzzdir", default=None,
        help="Input directory containing numerous sulley configs. (e.g. configs")

    # Output Directory
    opts.add_option("-o", "--output", action="store", type="string",
        dest="output_name", default=None,
        help="Directory to store output in %s." % G.OUTPUT_DIR)

    # Should we reboot first?
    opts.add_option("-R", action="store_false", dest="rebootfirst",
                    default=True,
                    help="Skip reboot.  Will not reboot the phone between fuzzing trials")

    # Check communication after each fuzz?
    opts.add_option("-C", action="store_false", dest="checkcomm",
                    default=True,
                    help="Skip communication test after fuzz input.  Will disable 'Hello World' after each input.")

    # Debug
    opts.add_option("-d", "--debug", 
                    dest="debug", 
                    action="store_true",  default=False,
                    help="Enable DEBUG output")

        
    (options, positionals) = opts.parse_args(args)

    # Get our log level
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Sanity checks
    if options.output_name is None:
        log.error("You must define an output directory.")
        opts.print_help()
        return

    if options.fuzzfile is None and options.fuzzdir is None:
        log.error("You must define an fuzz config file or a directory.")
        opts.print_help()
        return

#    import fcntl
#    import serial
#    tty = serial.Serial("/dev/ttyUSB4", baudrate=115200, timeout=0.05)
#    fcntl.flock(tty, fcntl.LOCK_UN)
#    tty.close()

    # setup our reader
    reader = rfidreader.NFCReader(device=options.reader)

    # setup our device to be fuzzed
    device = rfiddevice.AndroidPhone(type=G.PHONE_TYPES.NexusS,
                                     serial_num=options.adb_serial)

    device.checkjni_enable()

    device_comm_test = device.comm_test()
    if device_comm_test is not True:
        log.error("Cannot communicate with device. (try: adb devices)")
        log.error(device_comm_test)
        return
    # setup our input generator

    fuzz_inputs = {}

    def add_fuzz_input(filename):
        """
            Add a file to our input for fuzzing
        """
        # get the base name
        file_only = os.path.basename(filename)
        base_name = os.path.splitext(file_only)[0]

        # generate inputs
        fuzz_input_generator = Fuzz_Generator()
        fuzz_input_generator.read_config_file(filename)
        fuzz_output = fuzz_input_generator.generate().next()
        fuzz_inputs.update({base_name: fuzz_output})

    # Just 1 config?
    if options.fuzzfile is not None:
        if not os.path.exists(options.fuzzfile):
            log.error("%s does not exist." % options.fuzzfile)
            return
        add_fuzz_input(options.fuzzfile)

    elif options.fuzzdir is not None:
        if not os.path.exists(options.fuzzdir):
            log.error("%s does not exist." % options.fuzzdir)
            return

        for f in os.listdir(options.fuzzdir):
            if f.endswith(".py"):
                fname = os.path.join(options.fuzzdir, f)
                add_fuzz_input(fname)

    if fuzz_inputs is None:
        log.error("No fuzzing inputs provided!")
        return

    # define our fuzzer
    nfc_fuzzer = fuzzer.NDEFFuzzer(reader, device, sleep_time=10)

    # Connect to our reader
    if not reader.connect():
        log.error("Could not connect to reader!")
        log.error("PRO TIP: You may have to re-connect the USB cable or run the fuzzer as root.")
        return False

    # start fuzzing!
    fuzz_num = 0
    for fuzz_input in fuzz_inputs:

        fuzz_data = fuzz_inputs[fuzz_input]

        nfc_fuzzer._log("Starting fuzzing using '%s'" % fuzz_input)

        # Set our output directory
        output_dir = options.output_name
#        if options.fuzzdir is not None:
        output_dir = os.path.join(output_dir, fuzz_input)

        # Fuzz it!
        rtn = nfc_fuzzer.fuzz(fuzz_data, output_dir,
                              reboot_first=options.rebootfirst,
                              check_comm=options.checkcomm)

        if not rtn:
            continue

        fuzz_num += 1

    # Close our reader
    reader.close()


if __name__ == "__main__":
    main()
