"""
    This class abstracts our device that we will be fuzzing (e.g. an Android
    phone) to make it easy to interact with

    (c) 2015 Massachusetts Institute of Technology
"""
# Native
import os
import time
import subprocess
import logging
log = logging.getLogger(__name__)

# LL RFID Library
import globals as G

ENABLE_NFC_CMD = {
    G.PHONE_TYPES.NexusS: 0x5
    }

DISABLE_NFC_CMD = {
    G.PHONE_TYPES.NexusS: 0x4
    }


class RFIDDevice():
    """
        Place holder for now
    """
    def __init__(self):
        # Do nothing
        pass

class AndroidPhone(RFIDDevice):
    """
        This class is used to interact with an NFC enabled Android Phone over 
        ADB
    """
    def __init__(self, type="NexusS", serial_num=None):
        """
            Initialize our phone

        :param type: Type of phone (e.g. NexusS, Nexus4)
        :param serial_num: Serial number as returned by 'adb devices'
        :return:
        """
        self.type = type
        self.logging_proc = None
        self.serial_num = serial_num
        self.HAS_ROOT = self._check_root()

        if not self.HAS_ROOT:
            log.warn("This device does not appear to be rooted.")

        elif not self._has_scripts():
            # Upload our custom scripts
            self._upload_scripts()

            # Enable JNI output
            self.checkjni_enable()

    def _has_scripts(self):
        """
            Check to confirm that all of our scripts exist on the phone
        """
        for app in G.ANDROID_APPS:
            # Get our directories
            phone_app_path = os.path.join(G.ANDROID_APPDIR, app)

            rtn = self.adb_call(["shell", "su -c 'ls %s'" % phone_app_path])

            if rtn.find("No such file") != -1:
                return False
        # If we got here, we found all of them.
        return True

    def _upload_scripts(self):
        """
            Will upload some custom scripts to the phone that we use to control
            NFC and other applications
        """
        if not self.HAS_ROOT:
            log.warn("Phone is not rooted, custom scripts cannot be uploaded.")
            return

        # Create our directory
        self.adb_call(["shell", "su -c 'mkdir %s'" % G.ANDROID_APPDIR])

        # Chmod it
        self.adb_call(["su -c 'chmod 777 %s'" % G.ANDROID_APPDIR])

        for app in G.ANDROID_APPS:
            # Get our directories
            local_app_path = os.path.join(G.ANDROID_APPDIR_LOCAL, app)
            phone_app_path = os.path.join(G.ANDROID_APPDIR, app)

            # Push app to phone
            self.adb_call(["push", local_app_path, G.ANDROID_APPDIR])
            # Chmod it
            self.adb_call(["shell", "su -c 'chmod 777 %s'" % phone_app_path])

    def _check_root(self):
        """
            Check to see if the phone is rooted
            
            @return: True if the device is rooted, False otherwise.
        """
        rtn = self.adb_call(["shell", "su -c 'ls'"])

        if rtn.find("not found") != -1:
            return False
        else:
            return True

    def adb_call(self, command):
        """ Just a nice function to call adb """

        # Path to ADB
        cmd = ["adb"]

        # More than one device attached?
        if self.serial_num is not None:
            cmd.append("-s%s" % self.serial_num)

        # Run our command and wait for it to close
        c = subprocess.Popen(cmd + command, bufsize= -1,
                                            stderr=subprocess.STDOUT,
                                            stdout=subprocess.PIPE)
        rtn = c.wait()
        (stdout, stderr) = c.communicate()

        return stdout

    def comm_test(self):
        """
            Just test and confirm we can control the device
        """
        rtn = self.adb_call(["shell", "ls"])

        if rtn.find("error:") == -1:
            return True
        else:
            return rtn

    def reboot(self):
        """
            Reboot the device
        """
        rtn = self.adb_call(["reboot"])
        time.sleep(10)
        while not self.comm_test():
            time.sleep(1)

        time.sleep(45)
        return rtn

    def nfc_reset(self):
        """ This will kill the nfc and tag application on the phone """
        if not self.HAS_ROOT:
            log.warn("Phone is not rooted, nfc software reset disabled.")
            return
        self.adb_call(["shell", "su -c 'cd %s && ./reset_nfc'" %
                       G.ANDROID_APPDIR])

    def nfc_disable(self):
        """ Will disable the NFC service on the phone """
        if not self.HAS_ROOT:
            log.warn("Phone is not rooted, nfc software reset disabled.")
            return

        rtn = self.adb_call(["shell", "su -c 'service call nfc %d'" %
                                                    DISABLE_NFC_CMD[self.type]])

        should_be = "Result: Parcel(00000000 00000001   '........')"
        if (rtn != should_be):
            log.warn("Unexpected response shutting down NFC on phone")

    def nfc_enable(self):
        """ Will enable the NFC service on the phone """
        if not self.HAS_ROOT:
            log.warn("Phone is not rooted, nfc software reset disabled.")
            return

        rtn = self.adb_call(["shell", "su -c 'service call nfc %d'" %
                                                    ENABLE_NFC_CMD[self.type]])

        should_be = "Result: Parcel(00000000 00000001   '........')"
        if (rtn != should_be):
            log.warn("Unexpected response shutting down NFC on phone")

    def checkjni_enable(self):
        """
        Enables CheckJNI on the phone

        http://android-developers.blogspot.com/2011/07/debugging-android-jni-with-chckjni.html
        
        Ref: http://developer.android.com/training/articles/perf-jni.html
            
            adb shell stop
            adb shell setprop dalvik.vm.checkjni true
            adb shell start
        """

        # Restart runtime and enable JNI output
        self.adb_call(["shell", "su -c 'stop'"])
        self.adb_call(["shell", "su -c 'setprop dalvik.vm.checkjni true'"])
        self.adb_call(["shell", "su -c 'start'"])

    def get_logger(self, filename=None):
        return AndroidLogger(filename, self)


class AndroidLogger:
    """
        Logging for capturing logcat data from an Android device
    """
    def __init__(self, filename, android_device):
        """
            Initialize our logger

        :param filename: Filename for out output
        :param android_device: AndroidDevice object
        :return:
        """
        # Save our logfile location
        if filename is not None:
            directory = os.path.dirname(filename)
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, 775)
                except:
                    log.error("Could not make log directory!")
                    return None

        self.filename = filename
        self.android_device = android_device

    def start(self, clearFirst=True):
        """
            Start capturing logcat output and storing it in our file

        :param clearFirst: Should an existing file be wiped clean?
        :return:
        """
        # Clear backlogs?
        if clearFirst:
            self.android_device.adb_call(["shell", "logcat", "-c"])

        # Get our ADB path
        cmd = ["adb"]

        # More than one device attached?
        if self.android_device.serial_num is not None:
            cmd.append("-s%s" % self.android_device.serial_num)

        # open our subprocess into the backgroudn and let it run
        cmd.append("logcat")
        if self.filename is not None:
            # Write output to file
            self.logfile = open(self.filename, "a+")

            self.logging_proc = subprocess.Popen(cmd,
                                            bufsize= -1,
                                            stderr=self.logfile,
                                            stdout=self.logfile)
        else:
            self.logfile = None
            self.logging_proc = subprocess.Popen(cmd,
                                            bufsize= -1,
                                            stderr=subprocess.STDOUT,
                                            stdout=subprocess.PIPE)

        log.info("Started logger process...")

    def stop(self, clearAfter=False):
        """ Will stop logging """

        if self.logging_proc is not None:

            # Kill the running logcate process
            self.logging_proc.kill()

            log.info("Killed logger process.")

            if self.logfile is not None:
                # Write output to file
#                f = open(self.logfile, "w+")
#                f.write(stdout)
                self.logfile.close()
                return None
            else:
                # Get our output
                (stdout, stderr) = self.logging_proc.communicate()
                return stdout

        self.logging_proc = None

        # Clear backlogs?
        if clearAfter:
            self.android_device.adb_call(["shell", "logcat", "-c"])

        return None

    def check_for_crash(self):
        """ 
            This will look for some crash keywords in the log file and return 
            True if they're found

             TODO: Implement this
        """
        pass

