#!/usr/bin/python

import time
import os
import random
import binascii
import subprocess
import shutil
import subprocess

# this is for emulating type 2 tags with SCL3711 with a Nexus S talking to it.


#
# popen runs in the background.  close() waits for it to finish
# if you don't call close, I guess it just runs forever
#

adb = "../../../adt-bundle-linux-x86_64/sdk/platform-tools/adb"
bus = ""
device = ""
fd = -1 

# initalization
def init(ipaddy):
	global adb, bus, device

	try:
		os.unlink("information-pdus.txt")
	except:
		pass
	try:
		os.unlink("connect-pdus.txt")
	except:
		pass

	# figure out what bus/device our usb hub is on
	command = "lsusb"
	c = os.popen(command)
	line = c.read()
	loc = line.find("D-Link Corp. DUB-H7 7-port USB 2.0 hub")
	if loc > 0:
		bus = line[loc-29:loc-26]
		device = line[loc-18:loc-15]
	
	c.close()
	return True

def create_valid(title):
	# remove information file, otherwise this will override the supplied ndef
	try:
		os.unlink("connect-pdus.txt")
	except:
		print "Could not delete file"
        ret = ""
        ret += "d102"
        payload_len = 0x16 + len(title)
        ret += "%02x" % payload_len
        ret += "53709101"
        payload_len = 3 + len(title)
        ret += "%02x" % payload_len
        ret += "5402656e"+binascii.hexlify(title)
        ret += "51010b5501676F6F676C652E636F6D"
	data = binascii.unhexlify(ret)

	temp_file = open("ndef", "w")
	temp_file.write(data)
	temp_file.close()

        return ret

def disconnect_usb_reader():
	global bus,device
	command = "~/Downloads/hub-ctrl -b "+bus+" -d "+device+" -P 4 -p"
	c = os.popen(command)
	c.close()
#	time.sleep(1)

def connect_usb_reader():
	global bus,device
	command = "~/Downloads/hub-ctrl -b "+bus+" -d "+device+" -P 4 -p 1"
	c = os.popen(command)
	c.close()
	time.sleep(1)

def present_phone():
	global adb
	command = "timeout 3 " + adb + " shell \"su -c \\\"service call nfc 21\\\"\""
        c = os.popen(command)
        last_msg = c.read()
	c.close()
	last_msg = last_msg[:len(last_msg)-2]
	should_be = "Result: Parcel(00000000 00000001   '........')"
	if (last_msg != should_be):
		print "Unexpected response starting NFC on phone"
		reset_services()
		return False
	return True	

# when nfc service hangs, the popen below hangs... 
def remove_phone():
	command = "timeout 3 " + adb + " shell \"su -c \\\"service call nfc 20\\\"\""
        c = os.popen(command)
        last_msg = c.read()
	c.close()
	last_msg = last_msg[:len(last_msg)-2]
	should_be = "Result: Parcel(00000000 00000001   '........')"
	if (last_msg != should_be):
		print "Unexpected response shutting down NFC on phone"
		reset_services()
		return False
	return True	

def start_card_emulation():
#	command = "timeout -s 9 -k 10 10 python ./npp-test-client.py  --quirks=android -b < ndef 2>/dev/null"
#	c = os.popen(command)
	command = "python ./npp-test-client.py --mode=initiator --quirks=android -b < ndef &"
	subprocess.call(command, shell=True)
#	return c

def setup_ndef_for_emulation(ndef):
	return
	
def send_ndef(ndef):
#	disconnect_usb_reader() # necessary???
#	remove_phone()
#	time.sleep(1)
#	connect_usb_reader()
	present_phone()
	time.sleep(1)
	setup_ndef_for_emulation(ndef)
	emulation_fd = start_card_emulation()
#	present_phone()
	time.sleep(5)	#do test.
	remove_phone()
#	print "read1 ing"
#	out = emulation_fd.read()
#	print out
#	while len(out) > 0:
#		print "read2 ing"
#		out = emulation_fd.read()
#		print out
#	emulation_fd.close()  
#	print "done closing"
	return True

def get_last_msg():
	global adb
	command = adb + " shell \"su -c \\\"sqlite3 -line /data/data/com.google.android.tag/databases/tags.db 'select title from ndef_msgs where _id = (select MAX(_id) from ndef_msgs);'\\\"\""
        c = os.popen(command)
        last_msg = c.read()
	c.close()
	the_eq = last_msg.find("=")
	ret = last_msg[the_eq+2:len(last_msg)-2]
	return ret

def get_service_check(randnum):
	ndef = create_valid(randnum)
	send_ndef(ndef)
	return get_last_msg() 

def print_pids():
	global adb
	command = adb + " shell \"ps\""
       	c = os.popen(command)
        ps = c.read()
	c.close()
	nfc = ps.find("com.android.nfc")
	if nfc > 0:
		print "com.android.nfc: " + ps[nfc-45:nfc-39]
	tags = ps.find("com.google.android.tag")
	if tags > 0:
		print "com.google.android.tag: " + ps[tags-45:tags-39]

def check_for_crash():
	global adb
	time.sleep(1)
	command = adb + " logcat -d"
       	c = os.popen(command)
        log = c.read()
	c.close()
	if log.find("*** *** *** *** ***") > 0 or log.find('cpsr') > 0:
		print "CRASH"
		print log
		return True
	elif log.find("E/NfcService") > 0 or log.find("E/AndroidRuntime") > 0:
		print "OTHER"
		print log
		return True
	else:
		print " . "
		return False

def check_for_service():
	randnum = str(random.randrange(0, 99999999))
	last_msg = get_service_check(randnum)
	while(last_msg.find('database is locked') > 0):
		print "L",
		time.sleep(1)
		last_msg = get_last_msg()	
	if(last_msg == randnum):
#		print "Passed!"
		return True
	else:
		print "failed! |%s|%s|" % (randnum, last_msg)
        	disconnect_usb_reader() 
        	time.sleep(6)
	       	connect_usb_reader()
		return False

# get next test case
def get_testcase(filename):
	global fd
	# read infromation pdu from testcase file
	if fd == -1:
		fd = file(filename)
	ndef = fd.readline()
	if not ndef:
		return ""
#	ndef = ndef[:len(ndef)-1]

	# write information pdu to file read by llcp guy
	temp_file = open("connect-pdus.txt", "w")
	temp_file.write(ndef)
	temp_file.close()

	# put valid but useless pdu in place
	shutil.copy("ndef-good", "ndef")

#	while(len(ndef)%32):
#		ndef += "00"
	return ndef 

def clean_logs():
	global adb
	command = adb + " logcat -c"
	os.popen(command)
	
def reset_services():
	global adb
	command = adb + " shell \"su -c \\\"killall -9 com.android.nfc com.google.android.tag\\\"\""	
	c = os.popen(command)
	c.close()
	time.sleep(2)

def test_ndef(ndef):
	clean_logs()
	send_ndef(ndef)
	if check_for_crash():
		reset_services()
	while not check_for_service():
		print "SERVICE DOWN!!!"
		reset_services()
#	print_pids()

def test_casenum(filename, casenum):
	global fd
	ndef = get_testcase(filename)
	testnum=1
	while ndef and testnum <= casenum:
		if testnum==casenum:
			test_ndef(ndef)
		ndef = get_testcase(filename)
		testnum += 1	
	fd.close()
	fd = -1

def test_file(filename):
	ndef = get_testcase(filename)
	testnum = 1
	while ndef:
		print "%d: " % testnum,
		testnum += 1
		test_ndef(ndef)
		ndef = get_testcase(filename)
	print "Finished!"

#
# testing area
#

init("192.168.1.16")
#connect_usb_reader()
#ndef = get_testcase("bitflip.out")
#print ndef
#test_ndef(ndef)


test_file("bitflip.out")
#test_casenum("bitflip.out", 12)


#check_for_service()

#remove_phone()
#present_phone()

#clear_log()
#remove_phone()
#present_phone()
#print "watching"
#time.sleep(1)
#get_log()


#ndef = create_valid("hi")
#ndef = get_testcase("bitflip.out")
#print ndef
#ndef = get_testcase("bitflip.out")
#print ndef
#ndef = get_testcase("bitflip.out")
#print ndef



#check_for_service()
#print_pids()



