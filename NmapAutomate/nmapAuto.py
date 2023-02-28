#!/bin/python3
import argparse
import nmap

# TO DO
# Read from file - DONE. I think I've done this really shittly and need to figure out how to logic the var type better but it works.
# Custom NMAP scan to match external engagements
# Add dorky header when ran
#Output scan results to terminal in clean format

#MUST HAVE NMAP INSTALLED AND ON YOUR PATH
#Needed packages python-nmap, argparse
#pip install python-nmap argparse


#Little project to practice automating NMAP scans utilizing python.
#Going to start with a single IP and eventually have it read from a list of IPs


def nmapScan(ip, port):
    #NMAP SCAN HERE
    if type(ip) is list:
        for i in ip:
            scanResult = scanner.scan(i, port)
            f = open("TestNmapFile.txt", "a")
            f.write(str(scanResult))
    else:
        scanResults = scanner.scan(ip,port)
        f = open("TestNmapFile.txt", "a")
        f.write(str(scanResult))
    return print("Scan completed. Check file for scan results")

def getIP(ipAddressFile):
    #Get IP as a single IP or out of list
    file = open(ipAddressFile, 'r')
    ipList = file.read().split('\n')
    print(str(ipList))
    return ipList

#Get args for our scan
parser = argparse.ArgumentParser()

#Add args
parser.add_argument('--ip', type=str, required=False, help='The IP Address you would like to scan with NMAP')
parser.add_argument('--port', type=str, required=False, help='The Port you would like to scan for the IP you have provided')
parser.add_argument('--iL', type=str, required=False, help='The name of the txt file containing a list of IP addresses')
#Parse args
args = parser.parse_args()

#Create nmap scan
scanner = nmap.PortScanner()

#Check if list or single IP
if args.iL != None:
    ipToScan = getIP(args.iL)
else:
    ipToScan = args.ip

nmapScan(ipToScan, args.port)
#scanResults = scanner.scan(args.ip, args.port)
