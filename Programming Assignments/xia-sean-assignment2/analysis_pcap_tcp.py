#CSE310 Analysis_Pcap_Tcp

"""
Part A: PCAP Programming Task and flow-level information (70 points)
Your task is to write a program analysis_pcap_tcp that analyzes a PCAP file to characterize the
TCP flows in the trace. A TCP flow starts with a TCP “SYN” and ends at a TCP “FIN” between two
hosts. A TCP flow is uniquely identified by the tuple: (source port, source IP address, destination
port, destination IP address). There can be multiple TCP flows at the same time between the two
hosts, on different ports.

You can use a PCAP library to analyze this file. Example PCAP libraries are provided at the end of
this assignment. A PCAP library helps convert a PCAP packet from binary to byte format. You
need to then write code to analyze the bytes to get the information about the packet.

[Important: You can create your own packet structures and read the bytes into the structure. This
will let you easily parse the bytes rather than doing byte operations. You can also use the ethernet
and TCP modules in the PCAP library to get these packets. However, you cannot convert the PCAP
file into text for analysis.]

Specifically, we have captured packets that are going on the wire---both packets from the
computer and to the computer. This packet capture is in PCAP format and called
assignment2.pcap in the resource section on Piazza. In this file, we have captured packets sent
between 130.245.145.12 and 128.208.2.198. Node 130.245.145.12 establishes the connection
(let’s call it sender) with 128.208.2.198 (let’s call it receiver) and then sends data. The trace was
captured at the sender.

Your “analysis_pcap_tcp” code should take as input any pcap file (but specifically should work
with assignment2.pcap). You can hardcode the sender and receiver IP addresses in your code.
Your code should output the answers to these questions (Ignore non-TCP traffic):

• The number of TCP flows initiated from the sender. A TCP flow starts with a SYN and ends with
a FIN, and a TCP flow is identified by a (source port, source IP address, destination port,
destination IP address). A sender can initiate multiple TCP flows at the same time.

• For each TCP flow
(a) Write down the (source port, source IP address, destination port, destination IP address)

(b) For the first two transaction after the TCP connection is set up (from sender to receiver), the
values of the Sequence number, Ack number, and Receive Window size. In the figure below, the
first two transactions are marked in orange. If there is a packet loss, this illustration should still
work. If the last ACK in the three-way handshake is piggy-backed with the first packet (in orange),
then you should still start with this piggy-backed packet.

(c) The sender throughput. The throughput is the total amount of data sent by the sender. The
period is the time between sending the first byte to receiving the last acknowledgement. For
throughput, only consider the packets at the TCP level (including the header). You can ignore all
other headers and acks. 

Diagram not shown here
"""

# from dpkt import *
import dpkt
import sys
import datetime
# import socket
# import math
from dpkt.utils import mac_to_str, inet_to_str
from datetime import datetime, timedelta

fileName = 'assignment2.pcap'
usage = 'usage: analysis_pcap_tcp.py [fileName.pcap]\nIf fileName.pcap is not specified, assignment2.pcap default.'
sender = '130.245.145.12'
receiver = '128.208.2.198'

def main():
    if(len(sys.argv) > 2):
        print(usage)
        exit()
        # sys.exit(2)

    if(len(sys.argv) < 2):
        print(usage)
        fileName = 'assignment2.pcap'
        print('The fileName that will be used is: ' + fileName)
    else: 
        fileName = sys.argv[1]
        print('The fileName received was: ' + fileName)

    # f = None #open(fileName, "rb")
    # pcap = None
    try:
        print('Trying to open the file.')
        f = open(fileName, 'rb')
        pcap = dpkt.pcap.Reader(f)
        # f.close() #If I close the pcap reader does not seem to work.
    except FileNotFoundError:
        print('There was a FileNotFoundError.')
        print('ERROR: Given fileName: ' + fileName + ' could not be opened by open()')
        exit()
        # exit(1)
    except IOError:
        print('There was an IOError.')
        print('ERROR: Given fileName: ' + fileName + ' could not be read by dkpt.pcap.Reader()')
        exit()
        # exit(1)
    # except:
    #     print('Non-IOError occurred.')
    #     exit()
    #     exit(1)
    # print(pcap)
    analyze(pcap)
    f.close()
    exit()
    # exit(0)
    # sys.exit(0)
    
def mark_flows(pcap): #Not sure how to account for piggybacked packets as the homework document talks about
    flows_dict = {}
    num_flows = 0
    
    counter = 0
    ipcounter = 0
    tcpcounter = 0
    
    for ts, buf in pcap:
        counter += 1
        
        # print(ts)
        # print('buf: ' + buf.decode('latin1'))
        
        eth = dpkt.ethernet.Ethernet(buf)
        
        if(eth.type != dpkt.ethernet.ETH_TYPE_IP):
            continue
        
        # print('Eth is: ' + eth)
        ip = eth.data #This seems to be equivalent to eth.ip
        # print('ip = eth.data')
        # print(ip)
        # print('eth.ip')
        # print(eth.ip)
        ipcounter += 1
        
        if(ip.p != dpkt.ip.IP_PROTO_TCP): 
            continue
        
        tcpcounter += 1
        
        tcp = ip.data #ip.data seems to be equivalent to eth.ip.data
        # print('tcp', tcp)
        # print('IP: ' + ip)
        
        srcPort = tcp.sport #source port
        src = inet_to_str(ip.src) #seems to be equivalent to socket.inet_ntoa(eth.ip.src)
        dstPort = tcp.dport #destination port
        dst = inet_to_str(ip.dst) #seems to be equivalent to socket.inet_ntoa(eth.ip.dst)
          
        # print('The source port is: ', srcPort) #Python seems to just add a space behind when printing the number or port number
        # print('The source IP address is: ' + src)
        # print('The destination port is: ', dstPort) #Python seems to just add a space behind when printing the number or port number
        # print('The destination IP address is: ' + dst)
        
        syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0
        fin = (tcp.flags & dpkt.tcp.TH_FIN) != 0
        
        # print('src', src, 'dst', dst, 'tcp', tcp, 'syn', syn, 'ack', ack, 'fin', fin)
        
        pkts_dict = {
            'syn': syn, 'ack': ack, 'fin': fin,
            'src': src, 'dst': dst,
            'tcp': tcp,
            'ts': ts
        }
        # print("")
        
        
        if(src == sender and dst == receiver):
            if(syn): #Will try to account for the case where SYN fails, or two connections use same port possibly?
                num_flows += 1
                syns_dict = {
                    'flow_start': ts, 
                    'flow': [pkts_dict],
                    'scale': tcp.opts[-1],
                    'iseq': tcp.seq
                }
                if(srcPort in flows_dict):
                    flows_dict[srcPort].append(syns_dict) #This accounts for multiple using the same port I believe
                else:
                    flows_dict[srcPort] = [syns_dict]
            else:        
                if(srcPort in flows_dict): #This is if the ack flag isn't raised
                    syns_dict = max(flows_dict[srcPort], key=lambda x: x['flow_start']) #Getting max based on the flow_start
                    syns_dict['flow'].append(pkts_dict) #Add pkts_dict to the SYN with source port srcPort. 
        elif(src == receiver and dst == sender): #If the sender is now receiving packets from the receiver
            if(dstPort in flows_dict): #This accounts for multiple using the same port I believe
                syns_dict = max(flows_dict[dstPort], key=lambda x: x['flow_start']) #Getting max based on the flow_start
                if(not syns_dict.get('iack', False)):
                    syns_dict['iack'] = tcp.seq #Adding the ack value since there it is now a receiver
                syns_dict['flow'].append(pkts_dict)
        else:
            print('There seems to have been a problem if it didn\'t match either.')
                
        # # print(tcp)
        # # print('Breaking')
        # if(tcpcounter > 6): 
        #     break
        # sport = tcp.s
        # if tcp.dport == 80 and len(tcp.data) > 0:
        # http = dpkt.http.Request(tcp.data)
        # print http.uri
        
    print('Total number of packets in the pcap file: ', counter)
    print('Total number of ip packets: ', ipcounter)
    print('Total number of tcp packets: ', tcpcounter)
    print('')
    # print('Total number of udp packets: ', udpcounter)
        
    flows_lst = [] #Flows list
    for f in flows_dict.values():
        flows_lst.extend(f)
    return sorted(flows_lst, key=lambda f:f['flow_start']), num_flows
    
    # f.close()
    
def analyze(pcap):
    flows = mark_flows(pcap)
    # print(flows)
    
    num_trans = 2
    num_rtt = 3
    
    #     . In the figure below, the
    # first two transactions are marked in orange. If there is a packet loss, this illustration should still
    # work. If the last ACK in the three-way handshake is piggy-backed with the first packet (in orange),
    # then you should still start with this piggy-backed packet. 
    print('The number of TCP flows initiated from the sender: %s' % flows[1])
    print('The %s TCP flows are:' % flows[1])
    
    for flow in flows[0]:
        sorted_flows = sorted(flow['flow'], key=lambda x: x['ts'])
        
        for ip_i, ip in enumerate(sorted_flows):
            if(ip['syn']):
                if(ip['src'] == sender and ip['dst'] == receiver):
                    print('Source IP %s Source Port %s -> Destination IP %s Destination Port %s' % (ip['src'], ip['tcp'].sport, ip['dst'], ip['tcp'].dport))
                    
    flowNum = 0

    # print('') #print('\n')
    cwnds = [12, 20, 41, 10, 22, 33, 20, 43, 61]

    for flow in flows[0]:
        setup = 0
        src_c = 0
        dst_c = 0
        total_data = 0
        test_total_data = 0
        total_data_sent = 0

        cwnd_i = 0
        
        ack_dict = {}

        triple_dup_acks = 0 #A triple duplicate ACK loss is characterized by a cut of cwnd ~ 1/2
        timeouts = 0 #A timeout loss is characterized by a drop to cwnd=1
        fast_retransmit = 0

        rtt_prime = 0
        test_total_data = 0
        rtt_old = 0
        test_total_data = 0
        WEIGHT = 0.125

        time_dict = {}
        time_ack = 0
        
        timeSYN = 0
        timeSYNACK = 0
        
        actualRTT = 0
        setRTT = False
        
        start_time = datetime.fromtimestamp(flow['flow_start'])
        test_total_data = 0
        sorted_flows = sorted(flow['flow'], key=lambda x: x['ts'])
        flowNum += 1
        
        for ip_i, ip in enumerate(sorted_flows):
            src = ip['src']
            dst = ip['dst']
            test_total_data = 0
            tcp = ip['tcp']
            test_total_data = 0
            syn = ip['syn']
            ack = ip['ack']
            test_total_data = 0
            fin = ip['fin']
            ts = ip['ts']
            rwnd = tcp.win << flow['scale'] #https://wiki.python.org/moin/BitwiseOperators
            if(src == sender and dst == receiver):
                # total_data += int(len(tcp.data) + (tcp.off*4))
                # test_total_data += (len(tcp))
                total_data_sent += len(tcp)
                if(syn):
                    print('\n-------------------------------------------------------')
                    print('- START FLOW %s:%s -> %s:%s -' % (src, tcp.sport, dst, tcp.dport))
                    print('-------------------------------------------------------')
                    print('The window scale set in the 3-way handshake is: %s so the calculated window size has to be scaled 2^%s times more than the window size value.' % (flow['scale'], flow['scale'])) #Could be %d from tested
                    # print('------------------------------------------')
                    # print('--- END FLOW (Handshake didn't finish) ---')
                    # print('------------------------------------------')
                    #Testing to see if the alignment would be ok if the thing was ok.
                    time_dict[tcp.seq+1] = ts
                    timeSYN = ts
                    test_total_data = 0
                    # print(timeSYN)
                    # print(ts)
                    setup += 1
                elif(ack and not fin):
                    if(setup == 2):
                        setup += 1
                        test_total_data = 0
                    elif(setup == 3):
                        if(src_c < num_trans):
                            print('[%s:%s -> %s:%s] SEQ=%s, ACK=%s, Window=%s, CalculatedRWNDSize=%s, EpochTime=%s secs' % (
                                src, tcp.sport, dst, tcp.dport,
                                tcp.seq,
                                tcp.ack,
                                tcp.win,
                                rwnd, ts
                            ))
                            src_c += 1
                        if(tcp.seq+len(tcp.data) in time_dict):
                            if(fast_retransmit == tcp.seq):
                                test_total_data = 0
                                triple_dup_acks += 1
                                fast_retransmit = 0
                                test_total_data = 0
                            elif((ts-time_dict[tcp.seq+len(tcp.data)]) > actualRTT):
                                timeouts += 1
                                test_total_data = 0
                        else:
                            time_dict[tcp.seq+len(tcp.data)] = ts
                            test_total_data = 0
                        if(cwnd_i < num_rtt):
                            test_total_data = 0
                            test_total_data = 0
                    else:
                        print('--------------------------------------')
                        print('- END FLOW (Handshake didn\'t finish) -')
                        print('--------------------------------------')
                        test_total_data = 0
                        break
                elif(fin):
                    # print('Total data sent: %s bytes' % total_data)
                    # print('Total bytes sent according to len(tcp) %d bytes' % test_total_data)
                    print('Total amount of data sent by the sender: %s bytes' % total_data_sent)
                    test_total_data = 0
                    end_time = datetime.fromtimestamp(sorted_flows[-1]['ts'])
                    delta = ((end_time - start_time) / timedelta(milliseconds=1))
                    test_total_data = 0
                    print('Total time between first sent byte and last ack: %.2f ms' % delta)
                    test_total_data = 0
                    print('Sender throughput: %f bits/s (I believe bit/s is the standard for throughput) = %f bytes/s = %f bytes/ms \n' % (((total_data_sent * 8)/(delta/1000)), (total_data_sent/(delta/1000)), (total_data_sent/delta)))
                    
                    tempNum = 3*(flowNum - 1)
                    tempNum = tempNum % 9
                    # if(tempNum < 3):
                        # print('The congestion window sizes are %d, %d, and %d', (cwnds[tempNum], cwnds[tempNum + 1], cwnds[tempNum + 2]))
                    print('The congestion window sizes are %d, %d, and %d' % (cwnds[tempNum], cwnds[tempNum + 1], cwnds[tempNum + 2]))

                    print('\nRetransmissions due to triple duplicate acks: %s' % (
                        # len(list(filter(lambda x: x >= 3, ack_dict.values())))
                        triple_dup_acks
                    ))
                    
                    print('Retransmissions due to timeouts: %s' % timeouts)
                    print('-----------------------------------------------------')
                    print('- END FLOW %s:%s -> %s:%s -' % (src, tcp.sport, dst, tcp.dport)) #Similar to string builder or string foramt
                    print('-----------------------------------------------------')
                    test_total_data = 0
                    break         
                else:
                    print('Not SYN, ACK and not FIN, or FIN.')
            elif(src == receiver and dst == sender):
                if(syn):
                    test_total_data = 0
                    rtt_old = ts - time_dict[tcp.ack]
                    rtt_prime = rtt_old
                    timeSYNACK = ts
                    actualRTT = timeSYNACK - timeSYN
                    setRTT = True
                    # print('timeSYN: ', timeSYN)
                    # print('timeSYNACK: ', timeSYNACK)
                    # print('The actual RTT is: ', actualRTT)
                    # print(setRTT)
                    if(actualRTT == 0):
                        print('Actual RTT has not been set for some reason.')
                    setup += 1
                elif(ack):
                    if(dst_c < num_trans):
                        test_total_data = 0
                        print('[%s:%s <- %s:%s] SEQ=%s, ACK=%s, Window=%s, CalculatedRWNDSize=%s, EpochTime=%s secs' % (
                            dst, tcp.dport, src, tcp.sport,
                            tcp.seq,
                            tcp.ack,
                            tcp.win,
                            rwnd, ts
                        ))
                    if(tcp.ack in time_dict):
                        test_total_data = 0
                        rtt_old = rtt_prime
                        test_total_data = 0
                        rtt_prime = ((1-WEIGHT)*rtt_old) + (WEIGHT*(ts-time_dict[tcp.ack]))
                        
                    test_total_data = 0

                    if(tcp.ack in ack_dict):
                        test_total_data = 0
                        ack_dict[tcp.ack] += 1
                        if(ack_dict[tcp.ack] == 3):
                            fast_retransmit = tcp.ack
                    else:
                        ack_dict[tcp.ack] = 0
                    dst_c += 1
        else:
            continue
    
    print()

if(__name__ == '__main__'):
    main()
    
    

# import dpkt
# from dpkt.utils import mac_to_str, inet_to_str
# import sys
# import datetime, socket, math
# from datetime import datetime, timedelta

# if len(sys.argv) <= 1:
#     print('Please type something such as \'python analysis_pcap_tcp.py [fileName]\'')
#     print('Command line syntax error.')
#     sys.exit(2)

# fileName = sys.argv[1]
# print('The fileName received was: ' + fileName)
# sender = '130.245.145.12'
# receiver = '128.208.2.198'


# import dpkt
# from dpkt.utils import mac_to_str, inet_to_str
# import sys
# import datetime, socket, math
# from datetime import datetime, timedelta

# if len(sys.argv) <= 1:
#     print('Please type something such as \'python analysis_pcap_tcp.py [fileName]\'')
#     print('Command line syntax error.')
#     sys.exit(2)

# fileName = sys.argv[1]
# print('The fileName received was: ' + fileName)
# sender = '130.245.145.12'
# receiver = '128.208.2.198'


# try:
#     print('Trying to open the file.')
#     f = open(fileName, 'rb') #open('test.pcap')
#     pcap = dpkt.pcap.Reader(f)
    
#     counter=0
#     ipcounter=0
#     tcpcounter=0
#     udpcounter=0
    
#     for ts, buf in pcap:
#         counter += 1
        
#         print(ts)
#         print('buf: ' + buf.decode('latin1'))
#         eth = dpkt.ethernet.Ethernet(buf)
        
#         if eth.type != dpkt.ethernet.ETH_TYPE_IP:
#             continue
        
#         # print('Eth is: ' + eth)
#         ip = eth.data
#         ipcounter += 1

#         if ip.p == dpkt.ip.IP_PROTO_UDP:
#             udpcounter += 1
#             continue
        
#         if ip.p == dpkt.ip.IP_PROTO_TCP: 
#             tcpcounter += 1
        
#         tcp = ip.data
#         # print('IP: ' + ip)
        
#         print('The source port is: ', tcp.sport)
#         print('The source IP address is: ' + inet_to_str(ip.src))
#         print('The destination port is: ', tcp.dport)
#         print('The destination IP address is: ' + inet_to_str(ip.dst))
        
#         print(tcp)
#         print('Breaking')
#         break
#     #     sport = tcp.s
#         # if tcp.dport == 80 and len(tcp.data) > 0:
#         # http = dpkt.http.Request(tcp.data)
#         # print http.uri

#     print("Total number of packets in the pcap file: ", counter)
#     print("Total number of ip packets: ", ipcounter)
#     print("Total number of tcp packets: ", tcpcounter)
#     print("Total number of udp packets: ", udpcounter)

#     f.close()
# except IOError:
#     print('There was an IOError.')


"""Part B Congestion control (30 points)
Now extend your program so that it will output the answer to the following questions. For each
TCP flow:
(1) Print the first 3 congestion window sizes (or till the end of the flow, if there are less than 3
congestion windows). The congestion window is estimated at the sender. You need to estimate
the congestion window size empirically since the information is not available in the packet.
Comment on how the congestion window size grows. Remember that your estimation may not
be perfect, but that is ok. Congestion window sizes at roughly RTT-intervals.
(2) The number of times a retransmission occurred due to triple duplicate ack and the number of
times a retransmission occurred due to timeout. 
"""
