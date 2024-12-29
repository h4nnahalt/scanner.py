#!/usr/bin/env python3
from scapy.all import *
import signal
import sys
import time
import logging

def def_handler(sig, frame):
    sys.exit(1)

#Ctrl + C
signal.signal(signal.SIGINT, def_handler)
def scanPort(ip, port):
    src_port = RandShort()
    try:
       response = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port), timeout=2, verbose=0)

       if response is None:
           return False
       elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
           send(IP(des=ip)/TCP(sport=src_port, dport=port, flags="R"), vervose=0)
           return True

    except Exception as e:
        log.failure(f"Error scanning {ip} on port {port}: e")
        sys.exit(1)

def main(ip, ports):
    for port in ports:

        response = scanPort(ip, port)
        if response:
            log.info("Port {port} - OPEN")

if __name__ == '__main__':

    if len(sys.argv) !=3:
        print(f"[!] Uso: {('python3')} {(sys.argv[0])} {('<ip> <ports-range>')}",)
        sys.exit(1)

    target_ip = sys.argv[1]
    portRange = sys.argv[2].split("-")
    start_port = int(portRange[0])
    end_port = int(portRange[1])


    ports = range(start_port, end_port + 1)
    main(target_ip, ports)
