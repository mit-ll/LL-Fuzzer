                  ██╗     ██╗      ███████╗██╗   ██╗███████╗███████╗███████╗██████╗ 
                  ██║     ██║      ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
                  ██║     ██║█████╗█████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝
                  ██║     ██║╚════╝██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗
                  ███████╗███████╗ ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║
                  ╚══════╝╚══════╝ ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝

                       Authors: Chad Spensky (chad.spensky@ll.mit.edu)
                                  Hongyi Hu (hongyi.hu@ll.mit.edu)

================================================================================

  LL-Fuzzer is a fuzzing framework built to fuzz NFC applications on android 
devices.


# Dependencies

  * [NFCPy](https://launchpad.net/nfcpy)

  * [Sulley](https://github.com/OpenRCE/sulley)

  * [PyUSB](http://sourceforge.net/projects/pyusb/)

  * [Android Debug Bridge](http://developer.android.com/tools/help/adb.html)
 

# Hardware Requirements

  * [PN532 Breakout Board](http://www.adafruit.com/product/364)
  * [FTDI Cable](http://www.adafruit.com/products/70)


# Installation 

To install all of the dependencies type:
  
>$ ./install.sh
  
or follow the individual instructions below:

 * If you're using a 64bit machine, you must install the 32 bit libraries:

   >$ sudo apt-get install ia32-libs

 * Some of the android stuff requires java:

   >$ sudo apt-get install openjdk-7-jre

 * NFCPy depends on libusb:

   >$ sudo apt-get install python-pip
   
   >$ sudo pip install pyusb


# Usage 

For general help try:
>$ python fuzzer.py --help

An example of a real use case would be:
>$ python fuzzer.py -r tty:usb:0 -s 4d001f274acd31cf -D fuzz-configs/ndef/ -o testing

# Phone Setup 

  There are some settings on android that make fuzzing a much more pleasurable 
  experience.

  * Enable USB debugging through "Developer options"
    If you don't see this option go to "About phone" and tap the "Build number" 
    a bunch of times.

  * Enable "Stay awake" under "Developer options"

  * Set "Screen Lock" to None under "Security"


# Examples 

Here are some example commands to test NFC functionality (All files in examples-nfc):

 * Emulate an NFC tag:
   >$ ./npp-test-client.py -b --mode=initiator --quirks=android < ndef

 * Read data from an NFC tag:
    >$ ./tagtool.py


# Code Architecture

* RFID Reader / FrontEnd as named by nfcpy (e.g. Proxmark, Omnikey, PN532
board)
 - LL-Fuzzer provides full control over what this sends over the RFID channel

* RFID Device (e.g. smartphone, tablet, etc.)
 - Provides an abstraction to interaction with NFC-enabled devices

* RFID Message (e.g. NDEF, LLCP)
 - LL-Fuzzer supports numerous NFC message types

* Generator
 - Generates inputs for fuzzing

* Fuzzer
 - Drives fuzzing operation
 - Uses generator to generate fuzzed messages
 - Tells RFID reader to transmit fuzzed messages
 - Receives logs, etc. from RFID Device
 - Controls RFID stack on RFID device to reset state

# Mail 

It might be useful to interface the fuzzer with e-mail for very long jobs.
>$ sudo apt-get install sendmail


# Complications

## Unreliable RF Transmission
During our own fuzzing, we had a very difficult time getting reliable 
NFC communication.  To facilitate this, we used a book with the reader 
placed inside and the phone tapped to the top to prevent it from moving.  
A more elegant setup is certainly possible, but any reliable setup will 
need a way of tweaking the distance and then holding the reader and 
phone at that fixed distance for the duration of the fuzzing.

# Citation

Please use this DOI number reference, published on [Zenodo](https://zenodo.org), when citing the software:    
[![DOI](https://zenodo.org/badge/38062363.svg)](https://zenodo.org/badge/latestdoi/38062363)

# Disclaimer

This work is sponsored by the Defense Information Systems Agency under Air Force Contract #FA8721-05-C-0002.  Opinions, interpretations, conclusions and recommendations are those of the author and are not necessarily endorsed by the United States Government.
