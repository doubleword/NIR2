from scapy.all import *
import argparse



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
parser.add_argument('sender',help='senders\'s ip. Example: 192.168.0.1')
parser.add_argument('length',type=int,help='length of a message in bytes')


args=parser.parse_args()


msgSz=args.length*8
msgBv=[]


def processPacket(packet):
    
    global msgSz
    global msgBv
    
    if packet[IP].src==args.sender and packet.proto==17 and packet.sport==8080 and packet.dport==8080 and len(packet.options)>0:
        
        opts=bytes(packet[IP])[20:-len(packet[UDP])]
        #print(opts.hex())
        
        for i in range(3,len(opts),4):
            overflow=opts[i]>>4
            overflow=bin(overflow)[2:].rjust(4,'0')
            msgBv.extend( map(int,overflow) )
            msgSz-=4
        

def stopCallback(packet):
    global msgSz
    return msgSz==0


sniff(filter='ip',prn=processPacket,stop_filter=stopCallback)




msg=bitvectorToMsg(msgBv)
print('Received message:',msg)
