#!/usr/bin/python
import socket, sys
import binascii
from struct import *

def MAC_format(string):
	temp = list()
	for i in range(0,len(string),2):
		try:#01 23 45 67 
			temp.append(string[i:i+2])
		except:
			break;
	return ":".join(temp)

def data_hex_ascii(string):
	temp_str=""
	temp_lis=list()
	for i in range(0,len(string),2):
		if(i%32==0):
			temp_lis = temp_str.split(" ")
			for each in temp_lis:
				temp_str+=each.decode("hex")
			print temp_str
			temp_str = ""
		if(i%16==0):
			temp_str += " "
		temp_str += string[i:i+2]+" "





try:
	rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
while True:
	receivedPacket=rawSocket.recv(65565)
	ethernet_header=receivedPacket[0:14]
	eth=unpack("!6s6s2s",ethernet_header)
	ip_header = receivedPacket[14:34]
	iph=unpack("!12s4s4s",ip_header)
	tcp_header=receivedPacket[34:54]
	tcph=unpack("!2s2s16s",tcp_header)
	sourcePort=str(int(binascii.hexlify(tcph[0]),16))
	destinationPort=str(int(binascii.hexlify(tcph[1]),16))

	if(sourcePort=="80" or destinationPort=="80"):
		data = receivedPacket[66:]
		destinationMAC= MAC_format(binascii.hexlify(eth[0]))
		sourceMAC= MAC_format(binascii.hexlify(eth[1]))
		protocol= binascii.hexlify(eth[2])
		destinationIP=socket.inet_ntoa(iph[2])
		sourceIP=socket.inet_ntoa(iph[1])
		protocol = binascii.hexlify(iph[0])
		print "Destination MAC: " + destinationMAC
		print "Source MAC: " + sourceMAC
		print "Length: " +str(len(receivedPacket))
		print "Source IP: " + sourceIP
		print "Destination IP: " + destinationIP
		print "Source Port: " + sourcePort
		print "Destination Port: " + destinationPort+"\n"
		data_hex_ascii(binascii.hexlify(data))
		print "\n"