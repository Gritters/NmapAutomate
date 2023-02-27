#!/bin/python3
import argparse
import nmap

#MUST HAVE NMAP INSTALLED AND ON YOUR PATH
#Needed packages python-nmap, argparse
#pip install python-nmap argparse


#Little project to practice automating NMAP scans utilizing python.
# Going to start with a single IP and eventually have it read from a list of IPs

#Create our output file

#Get args for our scan
parser = argparse.ArgumentParser()

#Add args
parser.add_argument('--ip', type=str, required=True, help='The IP Address you would like to scan with NMAP')
parser.add_argument('--port', type=str, required=True, help='The Port you would like to scan for the IP you have provided')
#Parse args
args = parser.parse_args()

#Create nmap scan
scanner = nmap.PortScanner()

scanResults = scanner.scan(args.ip, args.port)

f = open("TestNmapFile.txt", "a")
for i in scanResults:
    f.write(str(i) + "\n")
f.close()
