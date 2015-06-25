"""
    LL RFID ReFuzzer
    
    Repeatedly fuzzes old input to try to reproduce crashes

    (c) 2015 Massachusetts Institute of Technology
"""

# Native
import logging
import optparse
import os
import re

# LL RFID Library
import llfuzzer.globals as G
import llfuzzer.fuzzer as fuzzer
import llfuzzer.rfidreader as rfidreader
import llfuzzer.rfiddevice as rfiddevice

def get_fuzz_input(fname):
    """
        Extract the raw input from a file

    :param fname: Filename with fuzzed input as content
    :return:
    """
    # open the file
    print "Reading '%s'" % fname

    f = open(fname, 'r')
    data = f.read()
    f.close()
    
    return data

def has_crash(fname):
    """
        Detect if a crash exists in the log file

    :param fname: Filename of logfile from trial
    :return:
    """
    f = open(fname, 'r')
    data = f.read()
    f.close()
    
    m = re.search("Fatal", data, re.DOTALL)
    
    if m is not None:
        return True
    else:
        return False

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

    # Fuzz input directory
    opts.add_option("-D", "--fuzzdir", action="store", type="string",
        dest="fuzzdir", default=None,
        help="Input directory. (Previously an output directory with results)")

    # Number of times to hit each fuzz case
    opts.add_option("-t", "--trials", action="store", type="int",
                    dest="trials", default=5,
                    help="Number of times to do each fuzz case. (Default 400)")

    (options, positionals) = opts.parse_args(args)

    if options.fuzzdir is None:
        print "ERROR: You must define an fuzz config file or a directory."
        opts.print_help()
        return

    # setup our reader
    print "Setting up reader . . ."
    reader = rfidreader.NFCReader(device=options.reader)

    # setup our device to be fuzzed
    device = rfiddevice.AndroidPhone(type=G.PHONE_TYPES.NexusS,
                                     serial_num=options.adb_serial)
    device.checkjni_enable()
    device_comm_test = device.comm_test()
    if device_comm_test is not True:
        print "ERROR: Cannot communicate with device. (try: adb devices)"
        print device_comm_test
        return

    # Does our directory exist?
    if not os.path.exists(options.fuzzdir):
        print "ERROR: %s does not exist." % options.fuzzdir
        return
    
    # Connect to our reader
    if not reader.connect():
        print "ERROR: Could not connect to reader!"
        print "-"
        print "PRO TIP: You may have to run the fuzzer as root."
        print "-"
        return False
        
    nfc_fuzzer = fuzzer.NDEFFuzzer(reader, device, sleep_time=10)

    # Loop over all of the outputs
    fuzz_num = 0
    for root, dirs, files in os.walk(options.fuzzdir):
        
        # Only trial directories will have a log and an input
        if "input.bin" in files and "device.log" in files:
            
            # See if this input crashed the device
            if has_crash(os.path.join(root,"device.log")):
                
                # Get our input to resend
                fuzz_data = get_fuzz_input(os.path.join(root,"input.bin"))

                print "Looks like %s had a crash, refuzzing..."%root
                
                # Fuzz it!
                rtn = nfc_fuzzer.refuzz(fuzz_data, root, options.trials)
        
                if rtn:
                    fuzz_num += 1
                    
    print "Done.  Refuzzed %d previous trials."%fuzz_num

    # Close our reader
    reader.close()


if __name__ == "__main__":
    main()
