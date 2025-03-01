from scapy.all import *
import hashlib

# CHAP 常量定义
CHAP_CHALLENGE = 1
CHAP_RESPONSE = 2
PPP_CHAP_PROTO = 0xC223

def generate_chap_response(identifier, challenge, password):
    return hashlib.md5(bytes([identifier]) + password.encode() + challenge).digest()

def handle_chap_challenge(packet):
    if PPP in packet and packet[PPP].proto == PPP_CHAP_PROTO and packet.load[0] == CHAP_CHALLENGE:
        print("Received CHAP Challenge")
        identifier = packet.load[1]
        challenge = packet.load[4:]
        response = generate_chap_response(identifier, challenge, password)
        
        chap_response_pkt = Ether(src=src_mac, dst=dst_mac) / PPP(proto=PPP_CHAP_PROTO) / \
                            Raw(load=bytes([CHAP_RESPONSE, identifier, 4+len(username)+len(response)]) + 
                                username.encode() + response)
        print("Sending CHAP Response")
        sendp(chap_response_pkt, iface=iface)

# MAC 地址 & 认证信息
src_mac, dst_mac = "00:11:22:33:44:55", "66:77:88:99:AA:BB"
username, password = "user", "password123"
iface = "eth0"

print("Sniffing for CHAP Challenge packets...")
sniff(iface=iface, filter=f"ether proto {hex(PPP_CHAP_PROTO)}", prn=handle_chap_challenge)
