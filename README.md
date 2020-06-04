# ARP-PROMISCUOUS-detection
detection of ARP attack &amp; PROMISCUOUS MODE

# Introduction
This script is all about Detecting few major attacks namely : ARP Poisoning and Promiscuous mode NIC. Here the Python Scripts which are developed will detect if any of the above mentioned attacks are running in the LAN. This is made accessible by linking the scripts to a simple GUI developed using tkinter, a Python package. Tkinter is a Python binding to the Tk GUI toolkit. It is the standard Python interface to the Tk GUI toolkit, The name Tkinter comes from Tk interface. Tkinter was written by Fredrik Lundh.
For the detection scripts Scapy is used. Scapy is a packet manipulation tool for computer networks, originally written in Python by Philippe Biondi. It can forge or decode packets, send them on the wire, capture them, and match requests and replies. It can also handle tasks like scanning, tracerouting, probing, unit tests, attacks, and network.
## ARP Poisoning
### What is ARP poisoning?
ARP spoofing is a type of attack in which an attacker sends false ARP (Address Resolution Protocol) messages over a local network (LAN). This results in the linking of an attacker's MAC address with the IP address of a legitimate machine on the network.

### How does it work ?

Once the attacker’s MAC address is linked to an authentic IP address, the attacker can receive any messages directed to the legitimate MAC address. As a result, the attacker can intercept, modify or block communicates to the legitimate MAC address.

### What is ARP attack in router ?

An ARP attack can be directed at “cheating” a host computer or a network router. If a router has the wrong MAC address for a given IP address, then all communications are routed to the wrong host.

 
### Detection of ARP Poisoning
Script: -

	from scapy.all import Ether, ARP, srp, sniff, conf
	import socket
	def get_mac(ip):
    		p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    		result = srp(p, timeout=10, verbose=False)[0]
    		return result[0][1].hwsrc
	def process(packet):
    		if packet.haslayer(ARP):
    			if packet[ARP].op == 2:
    				try:
    				real_mac = get_mac(packet[ARP].psrc)
    				response_mac = packet[ARP].hwsrc
    					if real_mac != response_mac:
    						print(f"[!] You are under attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
    					else:
    						print("Relax. You are not under attack")
    						except IndexError:
    						pass
	if __name__ == "__main__":
   	 import sys
   	 try:
       		iface = sys.argv[1]
    		except IndexError:
        		iface = conf.iface
    			sniff(store=False, prn=process, iface=iface)
## DEF GET_MAC (): -
 We declare function get_mac(ip) which requires a parameter ip.
	We then broadcast the destination MAC address to ensure that all packets are transmitted to all nodes in a subnet
	And then we combine the two packets to form a fully ARP request broadcast packet that will be sent to all the nodes in the subnet.
	In the srp () function, we set the packet we created as argument, timeout argument is set to 3 second. This means that the packet will wait 3 seconds for response before moving on to the next node.  	Next, we set the verbose argument to false, to limit the information outputted by the function to only the most relevant. 
	The function srp () return two lists. The first list contains the sent and the answered packets. The second list contains the unanswered packets. Now we set index to zero, [0] after a call to the function to make sure only the first list is assigned to variable answered_list.
	We return from the first list and the second list (which is the answered packet), we return the hwsrc field which is the MAC address of the source packet.
## Def Process (): -	
We use if statement to check if our packet has layer scapy.ARP using the has layer function, and if the op field of layer scapy.ARP of our packet is equivalent to 2. This signifies a response packet.	Now we assign the variable real_mac, with the value returned by the function get_mac () and we passed the source ip (psrc) of our packet as an argument. 
This will get the actual MAC address of the machine sending the packet.
	It initializes variable response_mac and assigns it with MAC address contained in the packet using the hwsrc field.
	It compares the real_mac with the response _mac and if they are not equal, that means the response_mac might have been spoofed!
	except Index Error: - Index Error might occur when our python script tries evaluating a packet, that is not destined to our machine. So, we except this error, and we asked the program to carry on with the code execution and ignore that error!

### Try block of main ():
Here we import the sys and take the input from system using sys.argv[1] and assign it to iface.

### In the except Index error:  
The conf.iface is used to get the iface value if the user doesn’t enter any interface value

### SNIFF FUNCTION: -
We define a function called sniff. This function sniff will sniff the packets passing through our interface. The iface argument of function sniff specifies the interface to sniff on. The argument store is used to specify whether our computer should store the packets in memory or otherwise. In this case, we do not want to store any packet, so we specify the value of store as false. Argument prn is used to specify a callback function. So, function sniff will first run, sniff packets, and call the callback function and passed the packets to it. Argument prn is assigned with function process which in this case is our callback function.

# Promiscuous Mode

Promiscuous mode is a type of computer networking operational mode in which all network data packets can be accessed and viewed by all network adapters operating in this mode. It is a network security, monitoring and administration technique that enables access to entire network data packets by any configured network adapter on a host system.
o	Promiscuous mode is used to monitor traffic.

In promiscuous mode, a network adapter does not filter packets. Each network packet on the network segment is directly passed to the operating system (OS) or any monitoring application. If configured, the data is also accessible by any virtual machine (VM) or guest OS on the host system.
Typically, promiscuous mode is used and implemented by a snoop program that captures all network traffic visible on all configured network adapters on a system. Because of its ability to access all network traffic on a segment, promiscuous mode is also considered unsafe. Like a system with multiple VMs, each host has the ability to see network packets destined for other VMs on that system.

## Detection of Promiscuous Mode
#### Script: -

    from scapy.all import Ether,ARP,srp


    def get_mac(ip):
	p=Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=ip)
	result=srp(p,timeout=3,verbose=True)[0]
	return result[0][1].hwsrc

    if __name__=="__main__":
	import sys
	ip=sys.argv[1]
	
	try:
		res=get_mac(str(ip))
		print("promiscuous")
	except:
		print("safe")
### DEF GET_MAC():
we declare function get_mac(ip) which requires a parameter ip.
we then broadcast the from a false MAC address “FF:FF:FF:FF:FF:FE”  to 				ensure that all packets are transmitted to all nodes in a subnet
we combine the two packets to form a fully ARP request broadcast packet that 				will be sent to all the nodes in the subnet.when a system is in Promiscuous Mode 				it will reply to that  packet 
In the srp() function, we set the packet we created as argument, 
timeout argument is set to 3 second. This means that the packet will wait 3 				seconds for response before moving on to the next node. 
Next we set the verbose argument to True, to get the information output by the 				function.
The function srp() return two lists. The first list contains the sent and the 					answered packets. The second list contains the unanswered packets. Now we set 				index to zero, [0] after a call to the function to make sure only the first list is 				assigned to variable answered_list.
we return from the first list and the second list (which is the answered packet), we 			return the hwsrc field which is the MAC address of the source packet.
Here we import the sys and take the input from system using sys.argv[1] and assign it to IP.
### In the Try Block : 
We call the GET_MAC(  ) function returning the corresponding values to “res”, When a NIC replies to the false Packet the TRY Block is executed, thus we know that particular NIC is in Promiscuous Mode
### In the Except Block : 
When there is no reply from any NIC in the LAN, there are no Promiscuous Mode NICs in the network.

