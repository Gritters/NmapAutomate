#!/bin/python3
import argparse
import nmap

#Little project to practice automating NMAP scans utilizing python.
#Going to start with a single IP and eventually have it read from a list of IPs

# TO DO
# I want to figure out how to print out the help if there are no arguments provided rather than an error.

#MUST HAVE NMAP INSTALLED AND ON YOUR PATH
#Needed packages python-nmap, argparse
#pip install python-nmap argparse

def nmapScan(ip, port):
    if port == 'all':
        #Loop through all ports for IP
        for x in range(65000):
            #NMAP SCAN HERE
            if type(ip) is list:
                for i in ip:
                    scanResult = scanner.scan(i, str(x))
                    f = open("TestNmapFile.txt", "a")
                    f.write(str(scanResult))
                    printToTerm(scanResult)
                    
            else:
                scanResult = scanner.scan(ip, str(x))
                f = open("TestNmapFile.txt", "a")
                f.write(str(scanResult))
                printToTerm(scanResult)   
   #Single Port
    else:
        if type(ip) is list:
                for i in ip:
                    scanResult = scanner.scan(i, port)
                    f = open("TestNmapFile.txt", "a")
                    f.write(str(scanResult))
                    printToTerm(scanResult)
                    
        else:
            scanResult = scanner.scan(ip, port)
            f = open("TestNmapFile.txt", "a")
            f.write(str(scanResult))
            printToTerm(scanResult)       
    return scanResult

def getIP(ipAddressFile):
    #Get IP as a single IP or out of list
    file = open(ipAddressFile, 'r')
    ipList = file.read().split('\n')
    return ipList

def printToTerm(scanResult):
    # HOLY SHIT this is terrible. Need to make it better but I can't figure out how to 
    # access the dictionary because the library names it nmap which is a keyword for lib.
    for k, v in scanResult.items():
                if k == 'scan':
                    for scankey, scanvalue in scanResult[k].items():
                        print("---------")
                        print(f"Host: {scankey}")
                        print("---------")
                        for hostkey, hostvalue in scanResult[k][scankey].items():
                            if hostkey == 'tcp':
                                for portKey, portValue in scanResult[k][scankey][hostkey].items():
                                    #Print the Port num and what service is running here
                                    print(f"Port")
                                    print("---------")
                                    print(f"{portKey} : {scanResult[k][scankey][hostkey][portKey].get('state')} - protocol : {scanResult[k][scankey][hostkey][portKey].get('name')}")
                                    print(f"Service : {scanResult[k][scankey][hostkey][portKey].get('product')} - Version : {scanResult[k][scankey][hostkey][portKey].get('version')}")
                                    print("---------")
                                    
                            elif hostkey =='hostnames':
                                for portKey, portValue in scanResult[k][scankey][hostkey]:
                                    #This portion of the dictionary randomly has it's values nested in a list
                                    for listDict in scanResult[k][scankey][hostkey]:
                                        for hKey, hValue in listDict.items():
                                            if hKey == 'name':
                                                print(f"Hostname: {hValue}")
                            # Have an elif for Addresses key and then add IP?
                            # Have status elif and print the state
                            elif hostkey == 'status':
                                print("---------")
                                print(f"Host is {scanResult[k][scankey][hostkey].get('state')}")
                                print("---------")          
    return
banner = """
   _____          __            _______      _____      _____ _____ ____
  /  _  \  __ ___/  |_  ____    \      \    /     \    /  _  \\______    \\
 /  /_\  \|  |  \   __\/  _ \   /   |   \  /  \ /  \  /  /_\  \|     ___/
/    |    \  |  /|  | (  <_> ) /    |    \/    Y    \/    |    \    |    
\____|__  /____/ |__|  \____/  \____|__  /\____|__  /\____|__  /____|    
        \/                             \/         \/         \/          
      """
print(banner)
#Get args for our scan
parser = argparse.ArgumentParser()

#Add args
parser.add_argument('--ip', type=str, required=False, help='The IP Address you would like to scan with NMAP')
parser.add_argument('--port', type=str, required=False, help='The Port you would like to scan for the IP you have provided')
parser.add_argument('--iL', type=str, required=False, help='The name of the txt file containing a list of IP addresses')
parser.add_argument('--Pl', type=str, required=False, help='Range or list of ports. EX - 80,443,8080')
parser.add_argument('--all', type=str, default='all', required=False, nargs='?', help="Scan ALL ports")

#Parse args
args = parser.parse_args()

#Create nmap scan
scanner = nmap.PortScanner()

#Check if list or single IP
if args.iL != None:
    ipToScan = getIP(args.iL)
else:
    ipToScan = args.ip

if args.Pl != None:
    results = nmapScan(ipToScan, args.Pl)
elif args.port !=None:
    results = nmapScan(ipToScan, str(args.port))
else:
    results = nmapScan(ipToScan, args.all)
print("Scan completed.")