
import scapy.all as scapy
import subprocess as sp
import time
import os

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=checkPacket)

def getIdx():
    # setting it by default to check the Wifi interface
    # TODO: prints a list of available interfaces at the start
    # of program and lets user choose which interface to monitor
    interfaceName = "Wi-Fi"
    cmd = "netsh interface ipv4 show interfaces"
    interface_process = sp.Popen(cmd,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True)
    output,error = interface_process.communicate()
##    print(interface_process.returncode)
    if interface_process.returncode!=0:
        return {'status':False,"error":error}
    else:
        li = output.split('\n')[1:-1]
##        print(li)
        for k in li:
            i = k.strip()
##            print(i)
            if i.find(interfaceName)!=-1:
                return {"status":True,"Idx":int(i.split(' ')[0])}
        return {"status":False,"error":"no interface found by that name"}

def checkARPtable():
    #first we get the Idx of the interface that we need to scan
    # idxJSON = getIdx()
    idx = hex(wifiIdx['Idx'])[1::]
##    print(idxJSON)
    # if idxJSON['status']:
    cmd = "arp -a"
    arp_process = sp.Popen(cmd,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,text=True)
    output,error = arp_process.communicate()
    if arp_process.returncode!=0:
        print("Some error:",error)
        return
    else:
        li = output.split('\n')
        li = li[1:-1]
        printit = False
        dynamicMACs = []
        
        for i in li:
            if i=="":
                continue
            if i.find('Interface')!=-1:
                if i.find(idx)!=-1:
                    printit=True
                else:
                    printit=False
            else:
                if printit:
                    if i.find('dynamic')!=-1:
                        dynamicMACs.append(i)

        for i in range(len(dynamicMACs)):
            q = dynamicMACs[i].split(' ')
            e = []
            for j in q:
                if j!="":
                    e.append(j)
            dynamicMACs[i] = e
        print(dynamicMACs)
    MAC_set = set()
    for i in dynamicMACs:
        if i[1] in MAC_set:
            print('ALERT!! You might be under attack. Please ensure using secure protocols!')
        else:
            MAC_set.add(i[1])
    MAC_set.clear()
        
    # else:
    #     print("Error in getting Idx:")
    #     print(idxJSON['error'])

def checkPacket(pkt):
    if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 2:
        time.sleep(3)
        checkARPtable()
        print("Received ARP packet")

wifiIdx = getIdx()
if wifiIdx['status']==False:
    print("Error in getting Idx:")
    print(wifiIdx['error'])
print(wifiIdx)
sniff('Wi-Fi')


