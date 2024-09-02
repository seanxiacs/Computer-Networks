### webservers.py
In this .py file, the socket and sys libraries were imported. The socket library was imported in order to communicate using sockets. The sys library was imported with the intention of exiting the program but was never used.

In order to run this program. you can press the play button on VSCode or type python webserver.py in the command line.

This python program can successfully serve the HelloWorld.html and dog.jpg image to your web browser by http://localhost:6789/HelloWorld.html and http://localhost:6789/dog.jpg after you have run the program. Other files may be supported if they are included in the same location as the code that is being run.

### proxyserver.py
In this .py file, the socket and sys libraries were imported. The socket library was imported in order to communicate using sockets. The sys library was imported in order to get the server host IP address from the person running the program. The usage in the command line is: python proxyserver.py [IP Address].

In order to run this program. You must enter a command on the command line in this format: python proxyserver.py [IP Address]. Please provide the IP address that you can see by typing 'ipconfig' in the command prompt of a Windows computer.

This python program can successfully serve webpages using HTTP/1.0. A list of some of the websites it supports are:
http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file2.html
http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file3.html
http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file4.html (Cannot serve the image from server kurose.cslash.net in France)
http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file5.html

