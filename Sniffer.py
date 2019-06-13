#Packet sniffer in python
#For Linux

import socket 
import struct
import binascii
import os

class unpack: 

 def __cinit__(self): 
   self.data=None

 #Ethernet Header 
 def ethernet(self, data): 
   store=data
   store=struct.unpack("!6s6sH",store)
   dest_mac=binascii.hexlify(store[0])
   src_mac=binascii.hexlify(store[1])
   ethernet_protocol=store[2]
   data={"Dest_Mac_addr":dest_mac,
   "Src_Mac_addr" :src_mac, 
   "Protocol" : ethernet_protocol} 
   return data 

  # ICMP HEADER Extraction 
  def icmp(self,data): 
   icmph=struct.unpack( '!BBH', data) 
   icmpType=icmph[0]
   code = icmph[1]
   chk_sum = icmph[2]
   data={ 'ICMP TYPE' :icmpType, 
   "Code" :code,
   "CheckSum":chk_sum}
   return data  




#create an INET, raw socket
s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

# receive a packet
while True:
	
	packet= s.recvfrom(65565)
	
	print (packet)
