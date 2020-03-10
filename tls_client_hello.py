import socket
import sys
from scapy.all import *
load_layer("tls")

host = (sys.argv[1],443)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_IP, socket.IP_TTL, int(sys.argv[2]))
s.connect(host)
s.setsockopt(socket.SOL_IP, socket.IP_TTL, int(sys.argv[3]))
sn = sys.argv[2]
sni = scapy.layers.tls.extensions.ServerName(servername=sn)
extensions = scapy.layers.tls.extensions.TLS_Ext_ServerName(type=0, servernames=sni)
#extensions = scapy.layers.tls.extensions.ServerName(servername='google.com')/scapy.layers.tls.extensions.TLS_Ext_ServerName()
#print extensions
handshake = scapy.layers.tls.handshake.TLSClientHello(ciphers=[0x7a7a,0x1301,0x1302,0x1303,0xc02b,0xc02c,0xc02f,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035,0x000a,0x009f],ext=extensions)
p = scapy.layers.tls.record.TLS(type=0x16,version=0x0301,msg=handshake)
#p = scapy.layers.tls.record.TLS(type=0x16,version=0x0303)/scapy.layers.tls.handshake.TLSClientHello()

p.show()

s.send(str(p))

r= s.recv(1024)
print(r)
s.close()
