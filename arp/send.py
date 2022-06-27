from scapy.all import *
import argparse
import random
import sys

#https://www.practicalnetworking.net/series/arp/traditional-arp/
#https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html?highlight=sniff(#scapy.sendrecv.bridge_and_sniff


def arpScan(target, networkInterface):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2,verbose=0)
    
    return [ p.pdst for p in list(unans)[1:-1] if p.pdst!=get_if_addr(networkInterface)]


def loadScanFromFile(f):
    s=f.read().split('\n')
    f.close()
    return s


def msgToBitvector(msg: str):
    return [1 if b&(0b10000000>>i) else 0 for b in msg.encode() for i in range(8) ]
    

def bitvectorToBytes(bv: list):
    msg=[]
    
    for i in range(0,len(bv),8):
        b=0
        for j,bit in enumerate(bv[i:i+8]):
            b|= bit<< (7-j)
        
        msg.append(b)
    
    return bytes(msg)


def bitvectorToMsg(bv:list):
    return bitvectorToBytes(bv).decode()



def generateMessages(unallocatedIPs,msg: str,seed=0xCAFE):
    
    # MSG: aa bb cc dd ee ff -> aa bb cc dd ee f0  and f0 00 00 00 00 0a
    #                                              ---------------padding (0xA*4 bits)
    # MSG: aa bb cc dd ee -> aa bb cc dd ee 01
    #                                       -padding (0x1*4bits)
    msgList=[]
    random.seed(seed)
    
    msgBv=msgToBitvector(msg)
    
    for i in range(0,len(msgBv),44):
        data=msgBv[i:i+44]
        
        assert len(data)%4==0,'Wrong amount of nibbles'
        
        ip=unallocatedIPs[ random.randrange(0,len(unallocatedIPs)) ]
        
        if len(data)==44:
            data+=[1]*4 if len(msgBv)==len(msgBv[:i+44]) else [0]*4
        else:
            paddingNibbles=44-len(data)
            
            assert paddingNibbles%4==0,'Wrong amount of nibbles'
            
            paddingNibbles//=4
            data+=[0,0,0,0]*paddingNibbles + msgToBitvector(chr(paddingNibbles))[4:]
        

        data=bitvectorToBytes(data).hex()
        data= ':'.join( [data[i:i+2] for i in range(0,len(data),2)] )
        
        msgList.append((ip,data))

    return msgList






parser = argparse.ArgumentParser()
parser.add_argument('target',help='receiver\'s ip/network prefix. Example: 192.168.0.1/24')
parser.add_argument('message',help='ASCII text to send')
parser.add_argument('-s','--scan',action='store_true',help='Scan for unallocated IPs and exit')
parser.add_argument('-f','--file',default=None,type=argparse.FileType('r'),
                    help='read a list of unallocated IPs from the file (IPs are new line separated)')
                        
parser.add_argument('-i','--interface',default=conf.iface,help='Name of the network interface. Picks default if unspecidied')    
args=parser.parse_args()




unallocatedIPs=arpScan(args.target,args.interface) if args.file is None else loadScanFromFile(args.file)
if args.scan:
    print('\n'.join(unallocatedIPs),end='')
    sys.exit(0)
    
    
messages=generateMessages(unallocatedIPs,args.message)
targetIP=args.target.split('/')[0]
targetMAC=getmacbyip(targetIP)

def processPacket(packet):
    global targetIP
    global targetMAC
    global messages
    
    #print('Process packet is called')
    ip,MACstego=messages[0]
    
    if packet.op==1 and packet.src==targetMAC and packet.hwsrc==targetMAC and packet.psrc==targetIP and packet.pdst==ip:
        
        response= Ether(dst=targetMAC) / ARP(op=2, hwsrc=MACstego, psrc=ip, hwdst=targetMAC, pdst=targetIP)
        sendp(response,verbose=0)
        messages.pop(0)
        
         
    
    #ls(packet)
    


def stopCallback(packet):
    global messages
    #print('\nStop callback is called\n')
    return len(messages)==0
    

for a,b in messages:    
    print(a,b,sep=' -> ') 
print()


sniff(filter='arp',iface=args.interface,prn=processPacket,stop_filter=stopCallback)


print('Sent.')    
   
    
