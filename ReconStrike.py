
#!/usr/bin/python


#Import Modules
import requests
import time
import sys
import urllib2
import nmap
import socket
import os
import subprocess
from os import system, name 

#Intro

time.sleep(2)

#Print Banner and Menu

def clear():
    _ = system('clear')

def Banner():

    print("""\033[1;31;40m


     ____                      ____  
    |  _ \ ___  ___ ___  _ __ / ___| 
    | |_) / _ \/ __/ _ \| '_ \\___ \ 
    |  _ <  __/ (_| (_) | | | |___)|
    |_| \_\___|\___\___/|_| |_|____/ 
                                    

    The All In One Recon Tool
    By: Qwertyboi21

    """)

def Menu():
    print("""\033[1;34;40m
    
    0. Exit
    00. Full Domain Scan
    1. Port Scan
    2. Whois Lookup
    3. DNS Lookup
    4. Subnet Banner Scan
    5. IP Location info
    6. Traceroute
    7. Subdomain Finder
    8. Crawler
    
    """)
clear()
    
Banner()


while True:


    Menu()

    #Ask for user input

    option = raw_input("\033[1;31;40mReconS#> ")

    #Port Scanner

    if option == "1":
        #Initialize the port scanner

        nmScan = nmap.PortScanner()

        #Ask user for target and ports

        Target = raw_input("\n[*] Please enter target(s) you want to scan: ")
        Ports = raw_input("[*] Please enter the ports that you want to scan: ")
        print("")
        print("[*] Scanning, please wait...")
        print("")

        #Scan Target ports
        nmScan.scan(Target, Ports)

        #Run a loop to print all the found result about the ports
        for host in nmScan.all_hosts():
            print('\033[1;32;40m[*] Host : %s (%s)' % (host, nmScan[host].hostname()))
            print('\033[1;32;40m[*] State : %s' % nmScan[host].state())
            print("")
            for proto in nmScan[host].all_protocols():
                print('Ports:\n')
                print("")
                print('\033[1;32;40m[*] Protocol : %s' % proto)
                print('')
                
                lport = nmScan[host][proto].keys()
                for port in lport:
                    print ('\033[1;32;40m[*] port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
                    print("")
                    print("")
    

    #Whois Lookup

    elif option == "2":

        #Define fetch

        def fetch(url, decoding='utf-8'):
            """Fetches content of URL"""
            return urllib2.urlopen(url).read().decode(decoding)

            #Lookup user input

        domip = raw_input('\n\033[1;91m[*] Enter Domain or IP Address: \033[1;m')
        who = "http://api.hackertarget.com/whois/?q=" + domip
        pwho = fetch(who)
        print("\033[1;32;40m" + pwho)

    elif option == "0":
        break

    #DNS Lookup

    elif option == '3':

        #Define fetch

        def fetch(url, decoding='utf-8'):
            """Fetches content of URL"""
            return urllib2.urlopen(url).read().decode(decoding)

        #Lookup user input

        domain2 = raw_input('\n\033[1;91m[*] Enter Domain: \033[1;m')
        ns = "http://api.hackertarget.com/dnslookup/?q=" + domain2
        pns = fetch(ns)
        print("\033[1;32;40m" + pns)

        #Detect cloudflare

        if 'cloudflare' in pns:
            print("\033[1;32;40m[*] Cloudflare Detected!\033[1;m")
        else:
            print("\033[1;32;40m[*] Not Protected By cloudflare\033[1;m")

#Subnet Banner Scan


    elif option == "4":
        ip = raw_input("[*] Please input your IP (Without last number, ex. 10.0.0.): ")
        print("\n[*] Scanning... (This might take a bit)\n ")
        def grab_banner(ip_address,port):  
            try:  
                s=socket.socket()  
                s.connect((ip_address,port))  
                banner = s.recv(1024)  
                print '\033[1;32;40m[*] ' + ip_address + ':' + banner  
            except:
                return
        def checkVulns(banner):  
            if len(sys.argv) >=2:  
                filename = sys.argv[1]  
                for line in filename.readlines():  
                        line = line.strip('\n')  
                        if banner in line:  
                            print "[*] %s is vulnerable" %banner  
                        else:  
                            print "[*] %s is not vulnerable"  
        def main():  
            portList = [21,22,25,80,110]  
            for x in range(0,255):  
                for port in portList:  
                        ip_address = ip + str(x)  
                        grab_banner(ip_address,port)  
        if __name__ == '__main__':  
            main()

    #Ip info lookup

    # Define fetch 
    if option == '5': 


        def fetch(url, decoding='utf-8'):
            """Fetches content of URL"""
            return urllib2.urlopen(url).read().decode(decoding)

        ip = raw_input('\n\033[1;91m[*] Enter IP Address: \033[1;m')
        geo = "http://ipinfo.io/" + ip + "/geo"
                
        try:
            pgeo = fetch(geo)
            print("\033[1;32;40m" + pgeo)

        except KeyboardInterrupt:
            print('\033[1;31m[-] Please provide a valid IP address!\033[1;m')


    #Trace Route

    #Define fetch

    def fetch(url, decoding='utf-8'):
        """Fetches content of URL"""
        return urllib2.urlopen(url).read().decode(decoding)

    if option == '6':
        domip = raw_input('\033[1;91mEnter Domain or IP Address: \033[1;m')
        trace = "https://api.hackertarget.com/mtr/?q=" + domip
        ptrace = fetch(trace)
        print("\033[1;32;40m" + ptrace)
    

    #SubDomain Finder
    if option == '7':
        #Ask for input
        a = raw_input("Please Enter a domain to scan: ")
        print("\nWhen you enough subdomains, just press Ctrl+C\n")
        print("All Valid subdomains will be printed in the ExistingSubdomains.txt file")
        time.sleep(2)
        #print the output of the Subdomain.py
        try:
            subprocess.call('python3 Subdomain.py -l subdomains.txt -t 20 ' + a, shell=True)
        except KeyboardInterrupt:
            print("\nFinishing up...")
            time.sleep(2)
            print("Remember, all valid subdomains are writen to the ExistingSubdomains.txt file")
            time.sleep(3)
            pass
    
            #Crawler

    if option == '8':
        import re, urllib

        try:

            subprocess.call('python3 Crawler.py', shell=True)
        except KeyboardInterrupt:
            pass

        if option == 'clear':
            def clear():
                _ = system('clear')
                
            clear()



        #Full Web Scan
    if option == '00':

        def fetch(url, decoding='utf-8'):
            """Fetches content of URL"""
            return urllib2.urlopen(url).read().decode(decoding)

        #DNS Lookup


        domain1 = raw_input('\n\033[1;91m[*] Enter Domain: \033[1;m')
        ip1 = socket.gethostbyname(domain1)

        print("\n[*] The Ip of your targt is" + " " + ip1)

        print("[*] DNS Look Up\n")
        raw_input("Press Enter When You Are Ready")
        time.sleep(1)

        ns = "http://api.hackertarget.com/dnslookup/?q=" + domain1
        pns = fetch(ns)
        print("\033[1;32;40m" + pns)

        if 'cloudflare' in pns:
            print("\033[1;31m[*] Cloudflare Detected!\033[1;m")
        else:
            print("\033[1;31m[*] Not Protected By cloudflare\033[1;m")

        print("\n")

        #Whois Lookup

        print("\033[1;31;40m[*] Whois Look Up\n")
        raw_input("Press Enter When You Are Ready ")
        time.sleep

        who = "http://api.hackertarget.com/whois/?q=" + domain1
        pwho = fetch(who)
        print("\033[1;32;40m[*] " + pwho)

        print("\n")

        #TraceRoute


        print("\033[1;31;40m[*] TraceRoute\n")
        time.sleep(1)

        raw_input("Press Enter to Start ")

        trace = "https://api.hackertarget.com/mtr/?q=" + domain1
        ptrace = fetch(trace)
        print("\033[1;32;40m[*] " + ptrace)

        print("\n")

        #Port Scan

        print("\033[1;31;40mPort Scan\n")

        nmScan = nmap.PortScanner()

        #Ask user for target and ports

        Target = domain1
        Ports = raw_input("[*] Please enter the ports that you want to scan: ")
        print("")
        print("[*] Scanning, please wait...")
        print("")

        #Scan Target ports
        nmScan.scan(Target, Ports)

        #Run a loop to print all the found result about the ports
        for host in nmScan.all_hosts():
            print('\033[1;32;40m[*] Host : %s (%s)' % (host, nmScan[host].hostname()))
            print('\033[1;32;40m[*] State : %s' % nmScan[host].state())
            print("")
            for proto in nmScan[host].all_protocols():
                print('Ports:\n')
                print("")
                print('\033[1;32;40m[*] Protocol : %s' % proto)
                print('')
                
                lport = nmScan[host][proto].keys()
                for port in lport:
                    print ('\033[1;32;40m[*] port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
                    print("")
                    print("")


        #Ip info look up
        raw_input("\033[1;31;40mIP Lookup: Press Enter when you are ready: ")
        geo = "http://ipinfo.io/" + ip1 + "/geo"
                
        try:
            pgeo = fetch(geo)
            print("\033[1;32;40m" + pgeo)

        except KeyboardInterrupt:
            print("Aborting scan")
            pass
        

        print("\033[1;31;40m[*] BruteForcing Domains")
        time.sleep(2)
        print("\nWhen you enough subdomains, just press Ctrl+C\n")
        print("All Valid subdomains will be printed in the ExistingSubdomains.txt file")
        raw_input("\nTo start press enter:")
        time.sleep(3)
        #Subdomain Bruteforce
        try:
            subprocess.call('python3 Subdomain.py -l subdomains.txt -t 20' + " " + domain1, shell=True)
        except KeyboardInterrupt:
            pass

        print("\n\033[1;31;40m[*] Crawling website")
        try:
            subprocess.call('python3 Crawler.py', shell=True)
        except KeyboardInterrupt:
            pass

        print("\n Thank you for using the basic verson 1 of ReconStrike. If you know any cool Python scripts that you think I could intagrate into ReconStrike, feel free to send them to me at Qwertyboi21 at Github")
