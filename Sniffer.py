#Packet sniffer in python
#For Linux

import socket 
import struct
import binascii
import re, uuid 
from uuid import getnode as get_mac
import datetime

def formatMacAddr(macAddr):
 NewmacAddr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(macAddr[0]), ord(macAddr[1]), ord(macAddr[2]), ord(macAddr[3]), ord(macAddr[4]) , ord(macAddr[5]))
 return NewmacAddr
 
class unpack: 

 def __cinit__(self): 
   self.data=None

 #Ethernet Header 
 def ethernet(self, data): 
   store=data
   store=struct.unpack("!6s6sH",store)
   #print (store)
   #dest_mac=binascii.hexlify(store[0])
   dest_mac=store[0]
   #dest_mac = get_mac()
   #des_mac = formatMacAddr(dest_mac)
   #src_mac=binascii.hexlify(store[1])
   src_mac=binascii = store[1]
   ethernet_protocol=store[2]
   data={"Dest_Mac_addr":dest_mac,
   "Src_Mac_addr" :src_mac, 
   "Protocol" : ethernet_protocol} 
   
   #print("Dest_Mac_addr: ", dest_mac)
   print("Source Mac_addr: ",src_mac)
   print("ethernetT proto :", ethernet_protocol)
   return data 

  # ICMP HEADER Extraction 
 def icmp(self, data):
   icmph=struct.unpack( '!BBH', data) 
   icmpType=icmph[0]
   code = icmph[1]
   chk_sum = icmph[2]
   data={ 'ICMP TYPE' :icmpType, 
   "Code" :code		,
   "CheckSum":chk_sum	}
   return data 
     
# ip header extraction
 def ipHeader(self , data):
  store = data
  storage = struct.unpack("!BBHHHBBH4s4s",data)
  ver = storage[0]
  tos = storage[1]
  totalLength = storage[2]
  ID = storage[3]
  frag_offSet = storage[3]
  timeToLive = storage [4]
  proto =storage[5]
  head_CK = storage[6]
  src_addr = socket.inet_ntoa(storage[8])
  dest_addr =socket.inet_ntoa(storage[9])
  print("source_addr ", src_addr)
  print("dest_addr ", dest_addr)
  print("sproto ", proto )
  data = { 'Version':ver,
   "Tos":tos,
   "Total Length": totalLength, 
   "Identification": ID,
   "Fragment": frag_offSet,
   "TTL":timeToLive,
   "Protocol":proto,
   "Header CheckSum": head_CK,
   "Source Address": src_addr,
   "Destination Address": dest_addr }
  return data


#TCP Header
def tcp(self, data):

  object=struct.unpack( ' !HHLLBBHHH',data)
  source_port= object[0]
  destination_port= object[1]
  sequence_num= object[2]
  acknowledge_num= object[3]
  offset= object[4]
  tcpFlag= object[5]
  window= object[6]
  checksum= object[7]
  pointer= object[8]
  data= {"Source Port":source_port,
   "Destination Port":destination_port,
   "Sequence Number":sequence_num,
   "Acknowledge Number":acknowledge_num,
   "Offset & Reserved":offset,
   "Tcp Flag":tcpFlag,
   "Window":window,
   "CheckSum":checksum,
   "Urgent Pointer":pointer
  }
  retrun data

  # UDP Header 
 def udp(self, data):
		
  object= struct.unpack('!HHHH', data)
  src_port = object[0]
  destination_port = object[1]
  length = object[2]
  checksum = object[3]
  data={"Source Port":src_port,
   "Destination Port":destination_port,
   "Length":length,
   "CheckSum":checksum}
  return data

 
def startSniff():

 #create an INET, raw socket
 
 #print('Starting Sniffing Session: {:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now()))
 from datetime import datetime
 SniffSession = f'{datetime.now():%Y-%m-%d %H:%M:%S%z}'
 print('Starting Sniffing Session')
 print (SniffSession)
 SaveFileName = "Sniffing_Session" + SniffSession
 SaveFileName = SaveFileName + ".txt"
 SaveFile = open(SaveFileName, "w+")
 SaveFile.write(SaveFileName)
 SaveFile.write("\n")
 SaveFile.close()
 Listing_Socket =socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
 #create a save file for this session 
 #DateSession = "Sniffer_Session:{:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()
 #receive a packet

 while True:
		
   Incoming_packets= Listing_Socket.recvfrom(65565)
   unpacker= unpack()
   printString = "{} : {} |"
	
   print("*************ETHERNAET HEADER**********************" + 'TIMESTAMP: {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))
   SaveFile = open(SaveFileName, "a+")
   SaveFile.write("*************ETHERNAET HEADER**********************" + 'TIMESTAMP: {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))
   SaveFile.write("\n")
  
  
   for items in unpacker.ethernet(Incoming_packets[0][0:14]).items(): 
    SaveFile = open(SaveFileName, "a+")
    x,y = items 
    SaveFile.write(printString.format(x,y))
    print (printString.format(x,y))
    SaveFile.write("\n")
    SaveFile.close()
  

   print("*************IP HEADER**********************" + 'TIMESTAMP: {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))
   SaveFile = open(SaveFileName, "a+")
   SaveFile.write("*************IP HEADER**********************" + 'TIMESTAMP: {:%Y-%m-%d %H:%M:%S}'.format(datetime.now()))
   SaveFile.write("\n")
   for items in unpacker.ipHeader(Incoming_packets[0][14:34]).items():  
    SaveFile = open(SaveFileName, "a+")
    x,y = items 
    SaveFile.write(printString.format(x,y))
    print (printString.format(x,y))
    SaveFile.write("\n")
    SaveFile.close()

startSniff()

 

  


