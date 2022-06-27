from scapy.all import *
import argparse
import random
import sys


def arpScan(target, networkInterface):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2,verbose=0)
    
    return [ p.pdst for p in list(unans)[1:-1] if p.pdst!=get_if_addr(networkInterface)]


def loadScanFromFile(f):
    s=f.read().split('\n')
    f.close()
    return s


def extractDataFromMAC(mac: str):
    
    paddingNibbles= 0 if mac[-1]=='f' or mac[-1]=='0' else int(mac[-1],16)
    #print(paddingNibbles)
    
    mac=''.join(mac.split(':'))
    mac=bytes.fromhex(mac)
    
   
    
    macBv= [1 if b&(0b10000000>>i) else 0 for b in mac for i in range(8) ]
    macBv=macBv[:44-4*paddingNibbles]
    
    return macBv



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







parser = argparse.ArgumentParser()
parser.add_argument('network',help='network ip (or host ip from the network)/network prefix. Example: 192.168.0.1/24')
parser.add_argument('-s','--scan',action='store_true',help='Scan for unallocated IPs and exit')
parser.add_argument('-f','--file',default=None,type=argparse.FileType('r'),
                    help='read a list of unallocated IPs from the file (IPs are new line separated)')
                        
parser.add_argument('-i','--interface',default=conf.iface,help='Name of the network interface. Picks default if unspecidied')    
args=parser.parse_args()




unallocatedIPs=arpScan(args.network,args.interface) if args.file is None else loadScanFromFile(args.file)
if args.scan:
    print('\n'.join(unallocatedIPs),end='')
    sys.exit(0)



random.seed(0xCAFE)

messageBv=[]

while True:
    ip=unallocatedIPs[random.randrange(0,len(unallocatedIPs))]
    print('ARP request for:',ip)

    request=Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    
    while True:
        response=srp1(request,timeout=1,verbose=0)
        if response is not None:
            break
    
    MACstego=response.hwsrc
    
    messageBv.extend(extractDataFromMAC(MACstego))
    
    if MACstego[-1]!='0':
        break




msg=bitvectorToMsg(messageBv)
print('Received message:',msg)

