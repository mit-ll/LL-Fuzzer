"""
    Script to generate known-good NDEF tags

    (c) 2015 Massachusetts Institute of Technology
"""
#!/usr/bin/env python

# =========================
# Generate good NDEF tags
#

import nfc.ndef

def write_to_file(string, filename):
    f = open('examples-data/ndef/'+filename, 'wb')
    f.write(string)
    f.close()


# ==========================
# Text Records

record = nfc.ndef.TextRecord("Hello World!")
message = nfc.ndef.Message(record)
write_to_file(str(message), "Text1")


# ==========================
# URIs

# Browser
record = nfc.ndef.UriRecord("http://nfcpy.org")
message = nfc.ndef.Message(record)
write_to_file(str(message), "Browser")

# Dailer
record = nfc.ndef.UriRecord("tel:5555555555")
message = nfc.ndef.Message(record)
write_to_file(str(message), "Dialer")


# Maps
record = nfc.ndef.UriRecord("geo:42.358769,-71.092081")
message = nfc.ndef.Message(record)
write_to_file(str(message), "Maps")


# Market
record = nfc.ndef.UriRecord("market://search?q=pname:com.google.android.maps")
message = nfc.ndef.Message(record)
write_to_file(str(message), "Market")


# SMS - needs testing b/c we haven't figure out how to set the payload
record = nfc.ndef.UriRecord("smsto:5555555555")
message = nfc.ndef.Message(record)
write_to_file(str(message), "SMS")



# ==========================
# Smart Posters

uri = "https://launchpad.net/nfcpy"
record = nfc.ndef.SmartPosterRecord(uri)
record.title = "Python module for near field communication"
message = nfc.ndef.Message(record)
write_to_file(str(message), "Smart-Poster1")


# ==========================
# Different MIME types


