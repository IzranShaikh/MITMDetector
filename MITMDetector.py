#MODULES
import subprocess as sp
import scapy.all as scapy
import sys
import smtplib
import re


#TITLE
sp.call('figlet -f standard "MITM Detector"',shell=True)


#WHILE !EXCEPTIONS
try:
    #GLOBAL VARIABLES
    BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END, BOLD, UNDERLINE, PURPLE, CYAN, DARKCYAN = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m', '\033[4m', '\033[95m', '\033[96m', '\033[36m'
    
   #Email and Password for Sending Mail with Google SMTP
    your_email = ""
    your_password = ""

    #METHODS
    class MITMDetector:
        def Send_Mail(self,email,password,message):
            self.smtp_mail_server = smtplib.SMTP('smtp.gmail.com',587)
            self.smtp_mail_server.ehlo()
            self.smtp_mail_server.starttls()
            self.smtp_mail_server.login(email,password)
            self.smtp_mail_server.sendmail(email,email,message) #From , To , Message Content
            print("[+] Execution Completed")
            self.smtp_mail_server.quit()

        def get_mac(self,targetip):
            self.arp_request = scapy.ARP(pdst=targetip)
            self.broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            self.arp_broadcast_request = self.broadcast/self.arp_request
            self.answered_packets = scapy.srp(self.arp_broadcast_request,timeout=1,verbose=False)[0]
            return self.answered_packets[0][1].hwsrc

        def ReadPackets(self,interface):
            print(GREEN+"\n[+] Reading Packets"+END)
            scapy.sniff(store=False,iface=interface,prn=self.ProcessSniffedPackets)

        def ProcessSniffedPackets(self,packets):
            if packets.hasLayer(scapy.ARP) and packets[scapy.ARP].op == 2:
                try:
                    self.real_mac = self.get_mac(packets[scapy.ARP].psrc)
                    self.response_mac = packets[scapy.ARP].hwsrc
                    if self.real_mac != self.response_mac:
                        print(RED+"\n[!] You are Under Attack"+END)
                        Send_Mail(your_email,your_password,"You are Under Attack")
                except IndexError:
                    pass

    #MAIN
    Md = MITMDetector()
    interface = str(raw_input("Enter the Interface Name"))
    Md.ReadPackets(interface)


#EXCEPTION HANDLING
except KeyboardInterrupt:
    print(RED+"\n\n[!] KeyboardInterrupt Occured!!!\nExiting ...\n"+END)
    quit()
