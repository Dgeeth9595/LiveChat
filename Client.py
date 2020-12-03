import socket
import sys
from multiprocessing import Process

class Client(object):
    
    def main(self):
        name = raw_input("Enter name : ") 
        print ("Hi "+name+", Enjoy Chatting! Type exit() to exit chat...\n")
        self.chat(name)
        
    def chat(self, name):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = ('localhost', 10000)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)
        sock.sendall(name)

        try:
            while True:
                msg = raw_input("You : ") 
                print (msg)

                # Send data
                if msg != ("exit()"):
                    message = msg
                    #print >>sys.stderr, 'sending "%s"' % message
                    sock.sendall(message)

                    # Look for the response
                    amount_received = 0
                    amount_expected = len(message)
                    
                    while amount_received < amount_expected:
                        data = sock.recv(16)
                        amount_received += len(data)
                        #print >>sys.stderr, 'received "%s"' % data
                else:
                    print >>sys.stderr, 'closing socket'
                    sock.close()
                    break

        finally:
            pass
            #print >>sys.stderr, 'closing socket'
            #sock.close()
    
if __name__ == '__main__':
    Client().main()