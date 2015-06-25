#!/usr/bin/python
"""

    This is a sample application to demonstrate some of the uses of the 
    LL RFID Library.
    
    (c) 2015 Massachusetts Institute of Technology
"""
#Native
import optparse
import time
import os

# LL RFID Library
import llfuzzer.globals as G
from llfuzzer.rfiddevice import AndroidPhone
from llfuzzer.rfidreader import NFCReader


def main(args=None):
    """
        Consume our user inputs and send message
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

    # Input file
    opts.add_option("-i", "--ndef_file", action="store", type="string",
        dest="ndef_file", default=None,
        help="Binary input for NDEF message.")

    # Reset NFC on the phone?
    opts.add_option("-R", "--reset", action="store_true",
        dest="nfc_reset", default=False,
        help="Do we want to reset the NFC applications before fuzzing?")

    (options, positionals) = opts.parse_args(args)

    if options.ndef_file is None or not os.path.exists(options.ndef_file):
        print "ERROR: ndef input file does not exist!"
        return

    # Initialize our phone

    if options.adb_serial is not None:

        print "Initializing phone..."
        device = AndroidPhone(type=G.PHONE_TYPES.NexusS, serial_num=options.adb_serial)

        device_comm_test = device.comm_test()
        if device_comm_test is not True:
            print "ERROR: Cannot communicate with device. (try: adb devices)"
            print device_comm_test
            return

        # Reset nfc processes
        if options.nfc_reset:
            device.nfc_reset()

        # Start logging
        device_log = device.get_logger()#"send_ndef.log")
        device_log.start(clearFirst=False)
    else:
        print "* No device given, sending the data anyway."

    ## Setup on reader (contactless front-end)
    print "Initializing reader..."
    reader = NFCReader(device=options.reader) #device="tty:usb:0"
    # Connect to our reader
    if not reader.connect():
        print "ERROR: Could not connect to reader!"
        return

    # Get our ndef data from the file
    print "Sending NDEF data..."
    f = open(options.ndef_file, "r")
    data = f.read()
    f.close()

    # Send data
    print "Sending NDEF data"
    reader.ndef_push(data)

    # Close up shop
    reader.close()
    print "Done."

    # Get log from device?
    if options.adb_serial is not None:
        time.sleep(1)
        device_log.stop()

if __name__ == "__main__":
    main()
