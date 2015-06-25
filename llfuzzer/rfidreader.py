"""
    This class abstracts our NFC/RFID reader to enable easy interaction

    (c) 2015 Massachusetts Institute of Technology
"""
#Native
import time
import os
import inspect
import logging
log = logging.getLogger()

# 3rd Party
import nfc.npp
import nfc.ndef
import nfc.llcp.pdu as pdu

# LL RFID Library
import globals as G

class RFIDReader:
    """
        Our super class, just a place holder for now
    """
    def __init__(self):
        pass

class NFCReader(RFIDReader):

    def __init__(self,
                 device="",
                 logfile=None,
                 mode=G.RFMODES.INITIATOR,
                 miu=1024,
                 android=False):
        """
            Initialize our RFID reader

            Use only device(s) that use the follow format:
                usb[:vendor[:product]] (vendor and product in hex)
                usb[:bus[:dev]] (bus and device number in decimal)
                tty[:(usb|com)[:port]] (usb virtual or com port)

        :param device: Address of our reader on the system
        :param logfile: File to log all the readers output too
        :param mode: Initialize as the initiator or target of communications
        :param miu: Maximum information unit size
        :param android: True/False will we be interacting with an Android
        device?
        :return:
        """
        # Set our variables
        self.MODE = mode
        self.ANDROID = android

        # Setup our logger
        verbosity = logging.INFO if G.DEBUG else logging.ERROR
        logging.basicConfig(level=verbosity, format='%(message)s')

        # Is a log file defined?
        if logfile != None:
            logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
            logfile = logging.FileHandler(logfile, "w")
            logfile.setFormatter(logging.Formatter(logfile_format))
            logfile.setLevel(logging.DEBUG)
            logging.getLogger('').addHandler(logfile)

        # More log stuff
        nfcpy_path = os.path.dirname(inspect.getfile(nfc))
        for name in os.listdir(nfcpy_path):
            if os.path.isdir(os.path.join(nfcpy_path, name)):
                logging.getLogger("nfc." + name).setLevel(verbosity)
            elif name.endswith(".py") and name != "__init__.py":
                logging.getLogger("nfc." + name[:-3]).setLevel(verbosity)

        # Debug?
        if G.DEBUG:
            logging.getLogger('').setLevel(logging.DEBUG)
            logging.getLogger('nfc').setLevel(logging.DEBUG)
            logging.getLogger("nfc.npp").setLevel(logging.DEBUG)
            logging.getLogger("nfc.llcp").setLevel(logging.DEBUG)
            logging.getLogger("nfc.dev").setLevel(logging.DEBUG)
            logging.getLogger("nfc.ndef").setLevel(logging.DEBUG)
            logging.getLogger("nfc.snep").setLevel(logging.DEBUG)

        # Setup our config
        self.llcp_config = {'recv-miu': miu, 'send-lto': 1000}

        # Special config for Android devices
        if android:
            self.llcp_config['send-agf'] = False

        self.devices = [device]

        self.CONNECTED = False

    def connect(self):
        """
            Connect to our physical reader
        """

        if self.CONNECTED:
            return True

        # Open our physical device
        for device in self.devices:
            try: self.clf = nfc.ContactlessFrontend(device); break
            except LookupError: pass
        else: return False

        self.CONNECTED = True
        return True

    def close(self):
        """
            Close connection with physical reader
        """
        self.clf.close()

    def ndef_push(self, data, send_raw=False):
        """
            Will use the NDEF Push Protocol (NPP) to send NDEF binary data

        :param data: Data to send
        :param send_raw: True/False is this RAW data?
        :return:
        """

        ndef_message = data

        if not send_raw:
            ndef_message = nfc.ndef.Message(data)

        general_bytes = nfc.llcp.startup(self.llcp_config)

        peer = self.__llcp_connect(self.clf, general_bytes)

        if peer is None:
            return False

        nfc.llcp.activate(peer)
        try:
            nfc.npp.NPPClient().put(ndef_message, send_raw=send_raw)
            while nfc.llcp.connected():
                time.sleep(1)
        except Exception as e:
            log.error("Exception: {0}".format(e))
            return False
        finally:
            log.info("Shutting Down.")
            nfc.llcp.shutdown()
            log.info("I was the " + peer.role)
            return True

        return True

    def send_llcp(self, packet, send_raw=False):
        """
            Send packet over LLCP protocol

        :param packet: LLC{ packet
        :param send_raw: True/False is this a RAW packet?
        :return:
        """

        general_bytes = nfc.llcp.startup(self.llcp_config)

        peer = self.__llcp_connect(self.clf, general_bytes)

        if peer is None:
            return False

        nfc.llcp.activate(peer)
        
        try:
            self.__send_llcp(peer, packet, send_raw=send_raw)
            
        except Exception as e:
            log.error("Exception: {0}".format(e))
            return False
            
        log.info("Deactivating peer.")
        nfc.llcp.deactivate()

        return True

    #
    #    Private Functions
    #

    def __send_llcp(self, peer, packet, send_raw=False, dsap=16):
        """
            Send llcp packet of type and payload.
            Assumes that a dsap is in range

        :param peer: Peer to communicate with
        :param packet: Packet to send
        :param send_raw: True/False is this a raw packet?
        :param dsap: Destination Service Access Port
        :return:
        """
 
        if not peer:
            log.error("send_llcp error - peer is None")
            return False

        # insert the dsap, which is the first 6 bits
        # default seems to be 16 at least on Nexus 4 for npp service
        if send_raw:
            new_byte = (ord(packet[0]) | 0xfc) & 0x43
            packet = chr(new_byte) + packet[1:]            

        log.info("Sending %s" % repr(str(packet)))

        try:
            # send PDU
            data = None
            
            if send_raw:
                data = peer.exchange(packet, 100)
            else:
                data = peer.exchange(packet.to_string(), 100)

            if data:
                resp = pdu.ProtocolDataUnit.from_string(data)
                logger.info("Received %s" % str(resp))
                #log.info("Received %s" % str(resp))
        except IOError:
            log.info("Did not receive response from peer within timeout.")
        except KeyboardInterrupt:
            log.debug("Aborted by user")
        finally:
            log.info("Disconnecting from peer.")

            dsap = 32
            ssap = 16

            disc_pdu = pdu.Disconnect(dsap, ssap)
            log.info("Sending Disconnect %s" % disc_pdu.to_string())
            peer.exchange(disc_pdu.to_string(), 100)

    def __llcp_connect(self, clf, general_bytes):
        """
            Connect to an LLCP peear

        :param clf: Contactless Front End
        :param general_bytes: bytes
        :return:
        """
        TIMEOUT = 30
        time_start = time.time()
        
        try:
            while True:
                if self.MODE == G.RFMODES.TARGET:
                    listen_time = 250 + ord(os.urandom(1))
                    peer = self.clf.listen(listen_time, general_bytes)
                    if isinstance(peer, nfc.DEP):
                        if peer.general_bytes.startswith("Ffm"):
                            return peer
                if self.MODE == G.RFMODES.INITIATOR:
                    peer = self.clf.poll(general_bytes)                    
                    if isinstance(peer, nfc.DEP):
                        if peer.general_bytes.startswith("Ffm"):
                            if self.ANDROID:
                                # Google Nexus S does not receive the first
                                # packet if we send immediately.
                                time.sleep(0.15)
                            return peer
                        
                # Make sure we eventualy timeout
                if time.time() - time_start > TIMEOUT:
                    log.error("LLCP connection timed out.")
                    return None
                
        except KeyboardInterrupt:
            log.debug("aborted by user")
