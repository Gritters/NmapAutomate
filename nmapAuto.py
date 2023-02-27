#!/bin/python3
import argparse
import nmap

#MUST HAVE NMAP INSTALLED AND ON YOUR PATH
#Needed packages python-nmap, argparse
#pip install python-nmap argparse


#Little project to practice automating NMAP scans utilizing python.
# Going to start with a single IP and eventually have it read from a list of IPs

#Create our output file

Port = "443"
IP = "127.0.0.1"

scanner = nmap.PortScanner()

scanResults = scanner.scan(IP, Port)

f = open("TestNmapFile.txt", "w")
for i in scanResults:
    f.write(str(scanResults))
f.close()
