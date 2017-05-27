#!/usr/bin/env python3
import socket
import sys
import subprocess
import ipaddress
import os
import struct
from tkinter import *

def run(*args):
    val = entryIp.value
    print(val)
def main():
    try:
        while(1):
            print("""\n-----------------------------VOLKAN HACKER TOOLS-----------------------------
||                                                                         ||
||                           1.Port Scanner                                ||
||                           2.Ip Scanner                                  ||
||                           3.Send Ping                                   ||
||                           4.Packet Sniffer                              ||
||                                                                         ||
-----------------------------------------------------------------------------""")
            print("Please Choose a Tool (1-4) :")
            chosen = input()

            if chosen == "1":
                portScanner()
            elif chosen == "2":
                ipScanner()
            elif chosen == "3":
                sendPing()
            elif chosen == "4":
                packetSniffer()
            else:
                print("Wrong Choise Try Again")

    except KeyboardInterrupt:
        sys.exit()

def portScanner():
    try:
        remoteServer = input("Enter a host to scan: ")
        remoteServerIP = socket.gethostbyname (remoteServer)

        print("-" * 60)
        print("Scanning...", remoteServerIP)
        print("-" * 60)

        for port in (20, 21, 22, 80, 443):
            print("port {} scanning ".format(port))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                info = socket.getservbyport(port)
                print("Port {}. Open -- {}".format(port, info))
            sock.close()

    except socket.gaierror:
        print('Hostname could not be resolved. Exiting')
        return

    except socket.error:
        print("Couldn't connect to server")
        return

    print('Scanning Completed.')
    return
def ipScanner():
    net_addr = input("Enter a network address in CIDR format(ex.192.168.1.0/24): ")
    ip_net = ipaddress.ip_network(net_addr)
    all_hosts = list(ip_net.hosts())

    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE

    for i in range(len(all_hosts)):
        output = subprocess.Popen(['ping', '-n', '1', '-w', '500', str(all_hosts[i])], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]

        if "Destination host unreachable" in output.decode('utf-8'):
            print(str(all_hosts[i]), "is Offline")
        elif "Request timed out" in output.decode('utf-8'):
            print(str(all_hosts[i]), "is Offline")
        else:
            print(str(all_hosts[i]), "is Online")
    return
def sendPing():
    ipaddr = input("Enter ip adress or hostname : ")
    command = "ping {}".format(ipaddr)
    print (os.system(command))
def packetSniffer():
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.connect(("8.8.8.8", 80))
    s.bind((s2.getsockname()[0],0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    while True:
        try:
            packet = s.recvfrom(65565)
            packet = packet[0]
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
            tcp_header = packet[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
            h_size = iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            data = packet[h_size:]
            print (data)
        except KeyboardInterrupt:
            sys.exit()
            pass

if __name__ == "__main__":
    main()
