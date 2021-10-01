import pyshark
# in the interface argument, put you interface through which packets come
# you can check it by opening wireshark, and the first option you would have to select your interface
# that same interface name you have input in the argument
# https://thepacketgeek.com/pyshark/intro-to-pyshark/
capture = pyshark.LiveCapture(interface='Wi-Fi')
capture.sniff(timeout=5)


for packet in capture:
    #ip_source = pkt.ip.__dict__["_all_fields"]["ip.src"]
    #ip_address = pkt.ip.__dict__["_all_fields"]["ip.dst"]

    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    print('Protocol:' + protocol + '\n' + 'source:' + source_address + '\n' + 'source port:' + source_port + '\n' + 'destination' + destination_address+'\n')

