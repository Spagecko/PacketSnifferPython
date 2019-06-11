#Packet sniffer in python
#For Linux

import socket 
import struct
import binascii
import os


#create an INET, raw socket
s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

# receive a packet
while True:
	print("no")
	packet= s.recvfrom(65565)
	print("do i work")
	print (packet)
