#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome, This is a beta tool")
print("<---------------------------->")

ipAddress = input("Enter Ip Address to be scanned : ")
print("The ip Address you entered is :", ipAddress)
type(ipAddress)

respond = input("""\nSelect Type of Scan
                    1)SYN ACK Scan
                    2)Comprehensive Scan
                    3)UDP Scan\n""")
print("Your Selected: ", respond)

if respond == '1':
    print("Nmap Version : ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports : ", scanner[ipAddress]['tcp'].keys())

elif respond == '2':
    print("Nmap Version : ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sS -sv -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports : ", scanner[ipAddress]['tcp'].keys())    

elif respond == '3':
    print("Nmap Version : ", scanner.nmap_version())
    scanner.scan(ipAddress, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status", scanner[ipAddress].state())
    print(scanner[ipAddress].all_protocols())
    print("Open Ports : ", scanner[ipAddress]['udp'].keys())

elif respond >= '4': 
    print("Enter Valid Option")   
