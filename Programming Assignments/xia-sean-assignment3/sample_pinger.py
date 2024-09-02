import os
import sys
import struct
import time
import select
import socket

ICMP_ECHO_REQUEST = 8
rtt_min = float('+inf')
rtt_max = float('-inf')
rtt_sum = 0
rtt_cnt = 0

def checksum(string):
    csum = 0
    countTo = (len(string) / 2) * 2

    count = 0
    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        # csum = csum & 0xffffffffL Need to remove the L Python V310
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(str) - 1])
        # csum = csum & 0xffffffffL Need to remove the L Python V310
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        #Fill in start

        #Fetch the ICMP header from the IP packet
        #recPacket[20:28] is part of data and is icmpHeader because it is bytes 20-28 which correspond to bits 160-224 so we unpack those bytes
        type, code, checksum, id, sequence = struct.unpack("bbHHh", recPacket[20:28]) #We need to get sequence number according to Additional NOtes for receiveOnePing but it is not in the output.
        if type != 0:
            return 'Type for packet ID {} must be set to 0, but it is {}'.format(ID, type)
        if code != 0:
            return 'Code for packet ID {} must be set to 0, but it is {}'.format(ID, code)
        if ID != id:
            return 'ID was expected to be {}, but it is {}'.format(ID, id)
        
        #Cannot do a check on the sequence number because sequence number is not passed into the receiveOnePing.
        timeSent,  = struct.unpack('d', recPacket[28:]) #The data that is packed into the packet is the time as shown by sendOnePing   
        #Have to keep the comma there because there would be a typeError: unsupported operand type(s) for -: 'float' and 'tuple'
        #It needs to be taken as a tuple.
        #Struct.unpack The result is a tuple even if it contains exactly one item according to https://docs.python.org/3/library/struct.html

        # length = len(recPacket) - 20
        length = len(recPacket)

        #We calculate rtt by subtracting receive and send time (now in s) and converting to ms by multiplying by 1000
        rtt = (timeReceived - timeSent) * 1000
        rtt_min = min(rtt_min, rtt) #Min is minimum of all previous mins and current rtt
        rtt_max = max(rtt_max, rtt) #Max is maximum of all previous maxes and current rtt
        rtt_sum += rtt #Sum is sum of all previous rtt and current rtt
        rtt_cnt += 1 #Add one to the rtt count

        #Did Shubham Jain write an article for DigitalOcean? https://www.digitalocean.com/community/tutorials/python-struct-pack-unpack
        #0 B unsigned char includes version and length
        #1 B unsigned char includes service type
        #2 H unsigned short includes packet length
        #3 H unsigned short includes identification
        #4 H unsigned short includes flags like DF MF and fragment offset
        #5 B unsigned char includes time to live
        #6 B unsigned char includes transport
        #7 H unsigned short includes header checksum
        #8 4s char[] includes source IP address
        #9 4s char[] includes destination IP address
        #https://python.readthedocs.io/en/latest/library/struct.html
        ip_header = struct.unpack('!BBHHHBBH4s4s' , recPacket[:20])
        ttl = ip_header[5] #In additional notes it says that we should fetch time to live (TTL) but not print it so I'm just leaving this here even though it isn't used in output.
        # print(ip_header[3]) #Testing to see if it would print the identification or identifier
        srcaddr = socket.inet_ntoa(ip_header[8]) #Get the source address

        #Whatever we return will be returned to doOnePing and then to ping which will print the string we return
        return '{} bytes from {}: time={:.3f} ms'.format(length, srcaddr, rtt)



        #Fill in end

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())  #8 bytes
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
        #Convert 16-bit integers from host to network byte order.
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    #Both LISTS and TUPLES consist of a number of objects
    #which can be referenced by their position number within the object

def doOnePing(destAddr, timeout):
    icmp = socket.getprotobyname("icmp")
    #SOCK_RAW is a powerful socket type. For more details see: http://sock-raw.org/papers/sock_raw
    
    #Fill in start
    
    #Create Socket here
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) 
    #(AF_INET is used for IPv4 protocols)
    #(SOCK_STREAM is used for TCP connections)
    #(SOCK_RAW to directly access IP Protocol)
    #Could apparently use socket.SOCK_DGRAM actually no
    #When using SOCK_DGRAM, get error OSError: [WinError 10043] The requested protocol has not been configured into the system, or no implementation for it exists

    #Fill in end
    
    myID = os.getpid() & 0xFFFF #Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay

def ping(host, timeout=1):
    global rtt_min, rtt_max, rtt_sum, rtt_cnt
    cnt = 0
    #timeout=1 means: If one second goes by without a reply from the server,
    #the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    # print "Pinging " + dest + " using Python:"
    print("Pinging " + dest + " using Python:")
    #Send ping requests to a server separated by approximately one second
    try:
        while True:
            cnt += 1
            # print doOnePing(dest, timeout)
            print(doOnePing(dest, timeout))
            time.sleep(1)
    except KeyboardInterrupt:
        
         #Fill in start
    
        #Calculate Statistics here
        
        if cnt != 0:
            print('^C--- {} ping statistics ---'.format(host)) #Including the "^C" to conform to the format given in the homework document since necessary to print to show in Windows VSCode terminal
            if rtt_cnt != 0: #To make sure that we actually got packets back and so we don't divide by 0 for rtt_avg calculation
                rtt_avg = rtt_sum / rtt_cnt
                #We can save min and max as we encounter rtts but rtt avg claculated at the end by dividing sum by thte count of all rtt encountered.
                print('round-trip min/avg/max {:.3f}/{:.3f}/{:.3f} ms'.format(rtt_min, rtt_avg, rtt_max))
            else:
                print('It seems that the all of the either ping or pong packets were lost in the network (or that all the server is down)')

        #Fill in end
        
if __name__ == '__main__':
    ping(sys.argv[1])