#CSE310 Web Proxy

"""
Part B. (50 points) Web Proxy
In this part of the assignment, you will learn how web proxy servers work and one of their basic
functionalities – caching.
Your task is to develop a small web proxy server which is able to cache web pages. It is a very
simple proxy server which only understands simple GET-requests, but is able to handle all kinds
of objects - not just HTML pages, but also images.
Generally, when the client makes a request, the request is sent to the web server. The web server
then processes the request and sends back a response message to the requesting client. In order
to improve the performance we create a proxy server between the client and the web server.
Now, both the request message sent by the client and the response message delivered by the
web server pass through the proxy server. In other words, the client requests the objects via the
proxy server. The proxy server will forward the client’s request to the web server. The web server
will then generate a response message and deliver it to the proxy server, which in turn sends it
to the client.

Diagram not shown here

Running the Proxy Server
Run the proxy server program using your command prompt and then request a web page from
your browser. Direct the requests to the proxy server using your IP address and port number.
For e.g. http://localhost:8888/www.google.com
To use the proxy server with browser and proxy on separate computers, you will need the IP
address on which your proxy server is running. In this case, while running the proxy, you will have
to replace the “localhost” with the IP address of the computer where the proxy server is running.
Also note the port number used. You will replace the port number used here “8888” with the
port number you have used in your server code at which your proxy server is listening.

Configuring your Browser
You can also directly configure your web browser to use your proxy. This depends on your
browser. For example, in Internet Explorer, you can set the proxy in Tools > Internet Options >
Connections tab > LAN Settings. You need to give the address of the proxy and the port number
that you gave when you ran the proxy server. You should be able to run the proxy and the
browser on the same computer without any problem. With this approach, to get a web page
using the proxy server, you simply provide the URL of the page you want.
For e.g. http://www.google.com

What to submit
Please submit the complete proxy server code (proxyserver.py) and screenshots at the client side
verifying that you indeed get the web page via the proxy server. 
"""

import socket
import sys

if len(sys.argv) <= 1:
    print('Please type something such as \'python proxyserver.py [IP Address]\'')
    print('Command line syntax error.')
    sys.exit(2)

#Creating a server socket
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

serverHost = sys.argv[1]
# serverHost = socket.gethostbyname(socket.gethostname()) #If have virtualbox IP address, apparently will not work so be careful. Can also use 'localhost' for this computer only
print('The entered server host IP is: ', serverHost)
serverPort = 8888 #maybe I should use port 80 instead?
# serverSocket.bind(('172.25.83.237',serverPort))10.1.173.12
serverSocket.bind((serverHost, serverPort))
serverSocket.listen(1) #Limit possible connections that are waiting for acceptance, how many connections we allow before we reject new ones, only want to listen for 1 at a time.

while True:
    print('Ready to accept requests.')
    connectionSocket, addr = serverSocket.accept()
    print('Received a connection from: ', addr)
    message = connectionSocket.recv(1024).decode('latin1') #.decode('latin1') #latin1 can apparently basically decode anything
    print('The message received is:  ', message)
    #If we receivet hese, we do not want to work with what we received.
    if(message.split()[1] == None):
        print('Passing message')
        continue
    if(message.split()[1] == '/www.google.com'):
        print('Passing message')
        continue
    if(message.split()[1] == '/www.google.com:443'):
        print('Passing message')
        continue
    if(message.split()[1] == 'mozilla.cloudflare-dns.com:443'):
        print('Passing message')
        continue
    if(message.split()[1] == 'contile.services.mozilla.com:443'):
        print('Passing message')
        continue
    if(message.split()[1] == 'incoming.telemetry.mozilla.org:443'):
        print('Passing message')
        continue
    if(message.split()[1] == 'firefox.settings.services.mozilla.com:443'):
        print('Passing message')
        continue
    if(message.split()[1] == '/favicon.io'):
        print('Passing message')
        continue
    if(message.split()[1] == 'spocs.getpocket.com:443'):
        print('Passing message')
        continue
    #contile.services.mozilla.com:443
    #spocs.getpocket.com:443
    #firefox.settings.services.mozilla.com:443
    
    #Get filename from message
    print('The website is: ', message.split()[1])
    filename = message.split()[1].partition('/')[2] #Is partition necessary? Yes, because we want to get everything after the first / in http:// or https://
    print('The filename is: ', filename)
    fileExist = 'false' #Flag to keep program updated if we have the file.
    try:
        #Check if file is in cache
        print('Will read cache with filename: ', filename[1:].replace('/', ''))
        f = open(filename.replace('/', ''), 'r')
        print('File was found.')
        outputdata = f.read()
        f.close()
        fileExist = "true"
        
        #Inform the client that everything is going ok.
        connectionSocket.send('HTTP/1.1 200 OK\r\n'.encode('utf_8'))
        #Apparently, the server does not need to give this for it to run.
        # connectionSocket.send('Content-Type: text/html\n'.encode('utf_8'))
        
        connectionSocket.send(outputdata)
        
        print('Sent Data')
        
        connectionSocket.close() #Should we close the socket here? I guess we have already ensured that we sent everything already.
        f.close()
        print('We read from the cache.')
        #Error handling for if the file is not found in cache
    except IOError:
        if fileExist == 'false':
            #Create a socket on the proxyserver in order to connect to the server we need to get the data from
            print('Cache was not found.')
            cSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hostn = filename.replace('www.', '', 1) #Do not want the www. when connecting to the server.
            hostn1 = hostn #Save the hostname just in case we need it later.
            if hostn != None and '.com' in hostn:
                hostn = hostn.partition('.com')[0] + '.com'
            elif hostn != None and 'net' in hostn:
                hostn = hostn.partition('.net')[0] + '.net'
            elif hostn != None and 'org' in hostn:
                hostn = hostn.partition('.org')[0] + '.org'
            elif hostn != None and 'edu' in hostn:
                hostn = hostn.partition('.edu')[0] + '.edu'
            elif hostn != None and 'gov' in hostn:
                hostn = hostn.partition('.gov')[0] + '.gov'
            else:
                print('Does not match .com, .net, .org, .edu, or .gov')
            
            print('connecting to', hostn) #hostn[1:])
            print(hostn[1:])
            try:
                # Connect to the socket to port 80
                cSocket.connect((hostn[1:], 80))
                print('Proxy server socket connected to port 80 of the host')

                #Isolate the file name for the GET request
                getFile = ''
                if filename != None and '.com' in filename:
                    getFile = filename.partition('.com')[2]
                elif filename != None and 'net' in filename:
                    getFile = filename.partition('.net')[2]
                elif filename != None and 'org' in filename:
                    getFile = filename.partition('.org')[2]
                elif filename != None and 'edu' in filename:
                    getFile = filename.partition('.edu')[2]
                elif filename != None and 'gov' in filename:
                    getFile = filename.partition('.gov')[2]
                else:
                    print('Does not match .com, .net, .org, .edu, or .gov')
                    
                print('Request to server sent: ', 'GET ' + getFile + ' HTTP/1.0\r\n\r\n')
                cSocket.send(('GET ' + getFile + ' HTTP/1.0\r\n\r\n').encode('utf_8'))
                buffer = cSocket.recv(262144) #2^18
                
                print('Will cache with filename ', filename.replace('/', ''))
                #Apparently / works with Windows file system in addition to \
                source = r'./'
                tmpFile = open(source + filename.replace('/', ''), 'wb') #open("./" + filename, "wb")

                tmpFile.write(buffer)
                print('Successfully saved')
                connectionSocket.send(buffer)
                tmpFile.close()
                connectionSocket.close()
                cSocket.close()
            except:
                print('Illegal request')
                connectionSocket.close()
                cSocket.close()
        else:
            # HTTP response message for file not found
            connectionSocket.send('HTTP/1.1 404 Not Found\r\n\r\n'.encode('utf-8'))
            response = '<html><body><center><h3>Error 404: File not found</h3><p>Python HTTP Server</p></center></body></html>'.encode('utf-8')
            connectionSocket.send(response)
            connectionSocket.close()

    # Close the client and the server sockets
    connectionSocket.close()
serverSocket.close()