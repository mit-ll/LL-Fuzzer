"""
    Some useful glboals for LL-Fuzzer

    (c) 2015 Massachusetts Institute of Technology
"""

# Check the version output from logcat (Seems to generally work for Android)
CHECK_VERSION = True
CHECK_VERSION_RETRIES = 3

# Android Applicaitons to send to phone
ANDROID_APPDIR_LOCAL = "android_scripts"
ANDROID_APPS = ["killall", "reset_nfc"]
ANDROID_APPDIR = "/data/data/edu.mit.ll.llfuzzer/"

# Where do we want the output to go?
OUTPUT_DIR = "./fuzzing_output"

# This is a log that we generate with errors etc.
LOGFILE_FUZZER = "fuzzer.log"
LOGFILE_DEVICE = "device.log"

NFC_BAD_VERSION = "Unable to read version"
# This is our known "good" tag and the output to search for in the logcat to confirm a good communicaiton
NFC_TAG_GOOD = "examples-data/ndef/Text1"
NFC_TAG_GOOD_OUTPUT = ["D/NfcDispatcher\([\d\s]+\): dispatch tag: TAG: Tech \[android.nfc.tech.Ndef\] message: NdefMessage \[NdefRecord tnf=1 type=54 payload=02656E48656C6C6F20576F726C6421\]" \
".*D/NfcHandover\([\d\s]+\): tryHandover\(\): NdefMessage \[NdefRecord tnf=1 type=54 payload=02656E48656C6C6F20576F726C6421\]",
"D/NfcService\([\d\s]+\): tag value :"]
#".*I/NfcDispatcher\([\d\s]+\): matched single TECH" \
#".*I/ActivityManager\([\d\s]+\): START \{act=android.nfc.action.TECH_DISCOVERED cmp=com.google.android.tag/com.android.apps.tag.TagViewer \(has extras\) u=0\}.*" \
#".*I/ActivityManager\([\d\s]+\): Displayed com.google.android.tag/com.android.apps.tag.TagViewer:"

# How many times should we try to reset the nfc software before moving to harsher measures
NFC_RESET_ATTEMPTS = 3
NFC_RESET_TIME = 5 # seconds

class PHONE_TYPES:
    NexusS = 1
    GalaxyS3 = 2

class RFMODES:
    INITIATOR = 1
    TARGET = 2
