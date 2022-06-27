from scapy.all import *
import argparse

#https://datatracker.ietf.org/doc/html/rfc781
#https://flylib.com/books/en/3.223.1.88/1/


def msgToBitvector(msg: str):
    return [1 if b&(0b10000000>>i) else 0 for b in msg.encode() for i in range(8) ]




parser = argparse.ArgumentParser()
parser.add_argument('target',help='receiver\'s ip. Example: 192.168.0.1')
parser.add_argument('message',help='ASCII text to send')


args=parser.parse_args()



msgbv=msgToBitvector(args.message)


for i in range(0,len(msgbv),20):
    data=msgbv[i:i+20]
    
    opts=[]
    for j in range(0,len(data),4):
        bv=data[j:j+4]
        
        overflow=bv[0]<<3 | bv[1]<<2 | bv[2]<<1 | bv[3]
        
        opt='44 04 05 '+hex(overflow)[2:]+'0'
        opts.append(opt)
    print(opts)
    opts=list(map(bytes.fromhex,opts))
    
    packet=IP(dst=args.target,options=opts)/UDP(sport=8080,dport=8080)/'UDP payload'
        
    send(packet)


print('Sent.')
