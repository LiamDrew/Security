#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

inc_num = 1

def display_alert(incident_number, incident, source_IP, protocol, payload):
    print(f"ALERT #{incident_number}: {incident} is detected from {source_IP} ({protocol}) ({payload})!")

def extract_and_decode_credentials(payload):
  # Search for the "Authorization: Basic" line in the payload
  for line in payload.splitlines():
    if "Authorization: Basic" in line:
      # Extract the base64 encoded string (remove "Authorization: Basic " prefix)
      encoded_credentials = line.split(" ")[-1].strip()
      
      # Decode the Base64 encoded credentials
      decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
      
      return decoded_credentials
  return None

def packetcallback(packet):
  global inc_num
  try:
    if TCP in packet:
      # Get flags and the source IP address
      flags = packet[TCP].flags
      source_IP = packet[IP].src if IP in packet else packet[IPv6].src

      # NULL Scan detection
      if (flags == 0):
        # Should I check if flags == 0 instead?
        display_alert(inc_num, "NULL scan", source_IP, "TCP", packet[TCP])
        inc_num += 1

      # FIN Scan detection
      if (flags == 0x01):
        display_alert(inc_num, "FIN scan", source_IP, "TCP", packet[TCP])
        inc_num += 1

      # XMAS scan detected
      if (flags & 0x29 == 0x29):
        display_alert(inc_num, "XMAS scan", source_IP, "TCP", packet[TCP])
        inc_num += 1
      
      # HTTP Authentication
      if packet[TCP].dport == 80 and Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "Authorization: Basic" in payload:
          display_alert(inc_num, "Credentials sent in cleartext with HTTP", source_IP, "HTTP", payload)
          print("Decoded Credentials: " + extract_and_decode_credentials(payload) + "\n")

      # FTP Credentials
      if packet[TCP].dport == 21 and Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "USER " in payload or "PASS " in payload:
          display_alert(inc_num, "Credentials sent in cleartext with FTP", source_IP, "FTP", payload)
          inc_num += 1
      
      # IMAP Cleartext credentials detection (port 21)
      if packet[TCP].dport == 143 and Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "LOGIN " in payload:
          display_alert(inc_num, "Credentials sent in cleartext with IMAP", source_IP, "IMAP", payload)
          inc_num += 1

      # Nikto scan
      if packet[TCP].dport == 80 and Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "Nikto" in payload or "nikto" in payload:
          display_alert(inc_num, "Nikto scan", source_IP, "HTTP", payload)
          inc_num += 1

      # SMB Scan
      if packet[TCP].dport in [139, 445]:
          protocol = "SMB"
          display_alert(inc_num, f"{protocol} scan", source_IP, protocol, packet[TCP])
          inc_num += 1

      # RDP Scan
      if packet[TCP].dport == 3389:
          protocol = "RDP"
          display_alert(inc_num, f"{protocol} scan", source_IP, protocol, packet[TCP])
          inc_num += 1

      # VNC Scan
      if packet[TCP].dport in range(5900, 5903):
          protocol = "VNC"
          display_alert(inc_num, f"{protocol} scan", source_IP, protocol, packet[TCP])
          inc_num += 1


  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    # print(e)
    pass



# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")