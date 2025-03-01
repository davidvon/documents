from scapy.all import *

# PAP 常量定义
PAP_AUTH_PROTO = 0xC023

# 发送 PAP 认证请求
def send_pap_auth():
    pap_payload = bytes([1, 1, len(username) + len(password) + 2]) + username.encode() + password.encode()
    pap_request_pkt = Ether(src=src_mac, dst=dst_mac) / PPP(proto=PAP_AUTH_PROTO) / Raw(load=pap_payload)
    print("Sending PAP Authentication Request")
    sendp(pap_request_pkt, iface=iface)

# 处理 PAP 认证应答
def handle_pap_response(packet):
    if PPP in packet and packet[PPP].proto == PAP_AUTH_PROTO:
        print("Received PAP Response")
        if packet.load[0] == 2:
            print("PAP Authentication Successful")
        else:
            print("PAP Authentication Failed")

# MAC 地址 & 认证信息
src_mac, dst_mac = "00:11:22:33:44:55", "66:77:88:99:AA:BB"
username, password = "user", "password123"
iface = "eth0"

# 发送 PAP 认证请求
send_pap_auth()

# 监听 PAP 认证应答
print("Sniffing for PAP Response packets...")
sniff(iface=iface, filter=f"ether proto {hex(PAP_AUTH_PROTO)}", prn=handle_pap_response)
