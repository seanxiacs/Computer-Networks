#CSE310 Web Server

"""
Part A. (50 points) Web Server
In this part of the assignment, you will learn the basics of socket programming for TCP
connections in Python: how to create a socket, bind it to a specific address and port, as well as
send and receive a HTTP packet. You will also learn some basics of HTTP header format.
Develop a web server that handles one HTTP request at a time. Your web server should be able
to (a) accept and parse the HTTP request, get the requested file from the server’s file system, (b)
create an HTTP response message consisting of the requested file preceded by header lines, and
then (c) send the response directly to the client. (d) If the requested file is not present in the
server, the server should send an HTTP “404 Not Found” message back to the client.
Running the Server
Put an HTML file (e.g., HelloWorld.html) in the same directory that the server is in. Run the server
program. Determine the IP address of the host that is running the server (e.g., 128.238.251.26).
From another host, open a browser and provide the corresponding URL. For example:
http://128.238.251.26:6789/HelloWorld.html
‘HelloWorld.html’ is the name of the file you placed in the server directory. Note also the use of
the port number after the colon. You need to replace this port number with whatever port you
have used in the server code. In the above example, we have used the port number 6789. The
browser should then display the contents of HelloWorld.html. If you omit ":6789", the browser
will assume port 80 and you will get the web page from the server only if your server is listening
at port 80.
Then try to get a file that is not present at the server. You should get a “404 Not Found” message.
What to submit
Please submit the complete server code (webserver.py) along with the screen shots of your client
browser, verifying that you actually receive the contents of the HTML file from the server
"""
    
# import socket module
# from socket import *
# from codecs import utf_8_encode
# from encodings import utf_8
import socket
import sys # In order to terminate the program

#serverHost = socket.gethostbyname(socket.gethostname()) #If have virtualbox IP address, apparently will not work so be careful. Can also use 'localhost' for this computer only
serverPort = 6789 #maybe I should use port 80 instead?

#Create a TCP server socket
#(AF_INET is used for IPv4 protocols)
#(SOCK_STREAM is used for TCP connections)
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Prepare a server socket
#Fill in start
serverSocket.bind(('', serverPort)) #Can apparently run without providing a serverHost
serverSocket.listen(1) #Limit possible connections that are waiting for acceptance, how many connections we allow before we reject new ones, only want to listen for 1 at a time.

print('The host IP might be (depends if you have other IP addresses):', socket.gethostbyname(socket.gethostname())) #Will return wrong IP address if you have Virtualbox IP address, better to use localhost:6789/HelloWorld.html on
print('The web server is up on port:', serverPort)

#Fill in end
while True:
    #Establish the connection
    print('Ready to accept requests.\n')
    #Set up a new connection from the client
    connectionSocket, addr = serverSocket.accept() #The socket is the one we use to communicate over, address is the address of the client that is connecting, and the socket that we can use to talk to that client. 
    
    try:
        #Receives the request message from the client
        print('Running.')
        message = connectionSocket.recv(1024).decode('latin1') #Prints the entire GET request
        print(message)
        filename = message.split()[1] #Looks like /HelloWorld.html
        f = open(filename[1:], 'rb') #Looks like HelloWorld.html, removing the /
        print('File was found.')
        outputdata = f.read()
        f.close()
        
        #Print outputdata originally used to print the HelloWorld.html but since we converted to make sure the webserver.py could handle things such as .jpg, cannot do a print on the binary files.
        # print(outputdata) 
        # print('\n\n\n')
        
        #Inform the client that everything is going ok.
        connectionSocket.send('HTTP/1.1 200 OK\r\n\r\n'.encode('utf_8'))
        
        #Apparently, the server does not need to give this for it to run.
        # connectionSocket.send('Content-Type: text/html\n'.encode('utf_8'))
        
        connectionSocket.send(outputdata)
        
        print('Sent Data')
        connectionSocket.close()
        continue
    except IOError:
        #Send response message for file not found
        #Then try to get a file that is not present at the server. You should get a “404 Not Found” message.
        print('File was not found.')
        connectionSocket.send('HTTP/1.1 404 Not Found\r\n\r\n'.encode('utf_8'))
        response = '<html><body><center><h3>Error 404: File not found</h3><p>Python HTTP Server</p></center></body></html>'.encode()
        connectionSocket.send(response)
        #connectionSocket.send('\n404 Not Found\r\n\r\n'.encode('utf-8'))
        
        connectionSocket.close()
        continue
        
        #Close client socket

#Unreachable code
# print('Reached end')       
# serverSocket.close()
# sys.exit() #Terminate the program after sending the corresponding data

#Example of a GET request
# GET /hello.htm HTTP/1.1
# User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
# Host: www.tutorialspoint.com
# Accept-Language: en-us
# Accept-Encoding: gzip, deflate
# Connection: Keep-Alive