We have tested this framework on two devices.  The Galaxy S3 and the Nexus S.

While rooting the phone is not required, the instructions for both are below.

# Nexus S
Below are instructions for rooting the Nexus S

## Flashing ROMs
How to Flash a Nexus Phone:


1. Download factory image from the Android Open Source Project:

	http://developers.google.com/android/nexus/images

2. Put device into fast boot mode.

	See http://source.android.com/source/building-devices.html

2a. If needed, unlock the boot loader.  Run 
    $ fastboot oem unlock

3. Run ./flash-all.sh in the factory image directory. 

## Rooting Device

I used this [tutorial](http://bernaerts.dyndns.org/phone/233-ubuntu-root-nexus-s-phone)

I used the following command to copy the Superuser App to the drive:

        cp Superuser-3.1.3-arm-signed.zip /media/22F6-14F1/


# Samsung Galaxy S3

I followed this [tutorial](http://galaxys3root.com/galaxy-s3-root/how-to-root-galaxy-s3-on-linuxubuntu/).

  Some additional commands that I used are below.  Happy Rooting!



First install libusb:

        sudo apt-get install libusb-1.0-0:i386

Then install heimdall:

        sudo dpkg -i heimdall_1.3.2_i386.deb

Now flash the recovery image:

        sudo heimdall flash --recovery recovery.img


Copy our SU App over to the device:

        gvfs-mount -l
        cp CWM-SuperSU-v0.87.zip ~/.gvfs/gphoto2\ mount\ on\ usb%3A002\,111/


