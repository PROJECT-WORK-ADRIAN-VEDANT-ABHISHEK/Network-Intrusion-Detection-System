import pyshark
# in the interface argument, put you interface through which packets come
# you can check it by opening wireshark, and the first option you would have to select your interface
# that same interface name you have input in the argument
capture = pyshark.LiveCapture(interface='Wi-Fi')
capture.sniff(timeout=5)
print(capture)

capture[0]