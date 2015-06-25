"""
    LLCP Client for sending raw LLCP packets

    (c) 2015 Massachusetts Institute of Technology
"""

# Native
import logging
log = logging.getLogger(__name__)
import time

# NFCpy
import nfc
import nfc.llcp
import nfc.llcp.pdu as pdu

# Maximum Information Unit
default_miu = 128


def info(message, prefix="LLCP Client: "):
    # print prefix+message
    log.info(prefix + message)

# Defaults are included, but don't seem to matter except for 0 and 1
def make_pdu(ptype, payload, dsap=1, ssap=32):
    """
        Make PDU based on ptype.
    """

    if ptype == 0b0000:
        return pdu.Symmetry()
    
    # if ptype == 0b0001:
    #     return ParameterExchange(dsap=dsap, ssap=ssap).from_string(s)
    # if ptype == 0b0010:
    #     return AggregatedFrame(dsap=dsap, ssap=ssap).from_string(s)
    
    if ptype == 0b0011:
        return pdu.UnnumberedInformation(dsap, ssap, payload)
    if ptype == 0b0100:
        return pdu.Connect(dsap, ssap, sn=payload)
    if ptype == 0b0101:
        return pdu.Disconnect(dsap, ssap)

    # if ptype == 0b0110:
    #     return ConnectionComplete(dsap=dsap, ssap=ssap).from_string(s)
    # if ptype == 0b0111
    #     return DisconnectedMode(dsap=dsap, ssap=ssap).from_string(s)
    # if ptype == 0b1000:
    #     return FrameReject(dsap=dsap, ssap=ssap).from_string(s)
    # if ptype == 0b1001:
    #     return ServiceNameLookup(dsap=dsap, ssap=ssap).from_string(s)
    
    if ptype == 0b1100:
         return pdu.Information(dsap, ssap, sdu=payload)
    
    # if ptype == 0b1101:
    #     return ReceiveReady(dsap=dsap, ssap=ssap).from_string(s)
    # if ptype == 0b1110:
    #     return ReceiveNotReady(dsap=dsap, ssap=ssap).from_string(s)

    else:
        info("Unrecognized ptype %s- cannot create PDU" % str(ptype))
        return None



class LLCP_Client(object):
    """
        Basic LLCP Client class that allows sending and receiving of
        LLCP packets
    """
    
    def __init__(self):
        self.socket = None
        
    def _connect(self, service_name):
        """
            Create connection-oriented socket
        """
        if self.socket:
            self._close()
        
        self.socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        nfc.llcp.connect(self.socket, service_name)
        peer_sap = nfc.llcp.getpeername(self.socket)
        
        log.debug("connection established with sap {0}".format(peer_sap))
        
        self.send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)
    
    def _connect_less(self, service_name):
        """
            Set up connection-less oriented socket
        """
        if self.socket:
            self._close()
        self.socket = nfc.llcp.socket(nfc.llcp.LOGICAL_DATA_LINK)
        
        # connect to dest sap?
        nfc.llcp.connect(self.socket, service_name)
        
        peer_sap = nfc.llcp.getpeername(self.socket)
        
        log.debug("connection established with sap {0}".format(peer_sap))
        
        self.send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)

    def _connect_raw(self, service_name):
        """
            Set up raw access point
        """
        if self.socket:
            self._close()
        self.socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
        nfc.llcp.bind(self.socket, None)

        # connect to dest sap?
        nfc.llcp.connect(self.socket, service_name)
        
        peer_sap = nfc.llcp.getpeername(self.socket)
        
        log.debug("connection established with sap {0}".format(peer_sap))
        
        # self.send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)

    def _close(self):
        """
            Close socket
        """
        if self.socket:
            nfc.llcp.close(self.socket)
            self.socket = None
            info("Socket closed.")

    def send_llcp(self, packet, send_raw=False, dsap=16):
        """
            Send llcp packet of type and payload.
            Assumes that a dsap is in range and activated as the peer
        """
        # poll and activate a peer
        peer = self.initiate_connection()
        
        # Don't need this - can just send raw stuff through DEP
        #if connectionless:
        #    #self._connect_less(service_name)
        #    self._connect_raw(service_name)
        #else:
        #    self._connect(service_name)
    
        if not peer:
            info("send_llcp error - peer is None")
            return

        # insert the dsap, which is the first 6 bits
        # default seems to be 16 at least on Nexus 4 for npp service
        if send_raw:
            new_byte = (packet[0] | 0xfc) & 0x43
            packet = new_byte + packet[1:]            

        info("Sending %s" % repr(str(packet)))

        try:
            # send PDU
            data = None
            
            if send_raw:
                data = peer.exchange(packet, 100)
            else:
                data = peer.exchange(packet.to_string(), 100)

            if data:
                resp = pdu.ProtocolDataUnit.from_string(data)
                info("Received %s" % str(resp))
        except IOError:
            info("Did not receive response from peer within timeout.")
        except KeyboardInterrupt:
            info("Aborted by user")
        finally:
            info("Disconnecting from peer.")
            disc_pdu = make_pdu(0b0101, packet.dsap, packet.ssap)
            peer.exchange(disc_pdu.to_string(), 100)
            
            info("Deactivating peer.")
            nfc.llcp.deactivate()

    def initiate_connection(self):
        """
            Polls for an NFC peer and activates the peer.
        """
        
        llcp_config = {'recv-miu': default_miu, 'send-lto': 500}
        # if options.quirks == "android":
        llcp_config['send-agf'] = False
    
        general_bytes = nfc.llcp.startup(llcp_config)
        try: clf = nfc.ContactlessFrontend("");
        except LookupError:
            info("Could not open NFC reader.")
            return
    
        peer = None
        info("Polling for peer . . .")
        try:
            while True:
               # if options.mode == "target" or options.mode is None:
               #     listen_time = 250 + ord(os.urandom(1))
               #     peer = clf.listen(listen_time, general_bytes)
               #     if isinstance(peer, nfc.DEP):
               #         if peer.general_bytes.startswith("Ffm"):
               #             break
                # if options.mode == "initiator" or options.mode is None:
                peer = clf.poll(general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        # if options.quirks == "android":
                            # Google Nexus S does not receive the first
                            # packet if we send immediately.
                        time.sleep(0.1)
                        break
        except KeyboardInterrupt:
            info("Polling aborted by user")
            clf.close()
            return None
    
        info("Found peer %s" % str(peer))

        nfc.llcp.activate(peer)
        time.sleep(0.5)
        return peer
