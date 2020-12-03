import socket
import sys
from multiprocessing import Process

class Server(object):

    def main(self):
        self.connectionsStack = []
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        server_address = ('localhost', 10000)
        print >>sys.stderr, 'starting up on %s port %s' % server_address
        self.sock.bind(server_address)

        # Listen for incoming connections
        self.sock.listen(128)

        # 1. Need a way to listen to connection and for messages simultaniously. 
            # (Multiprocess uses diff memory but GIL)
            # (Multithreading uses same memory so can't listen for connections and messages simultaneously)
        # 2. Print the names in different colours in terminal (Neaten it out)
            # https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
        # 3. Add encryption process
            # i.   Generate RSA keys (Public Private key)... publish public key while establishing connection
            # ii.  Generate DH key using Public/Private keys (on Server and Clients side)
            # iii. Encrypt using DH Key AES Encryption

            # iv.  Decrypt and print message on server side. Encrypt and Broadcast message to all other clients.
            # v.   Decrypt and print message on client side
        # 4. Handle following situation
            # i. Leaving chat

    
    def listForConnections(self):
        while True:
            # Wait for a connection
            print >>sys.stderr, 'waiting for a connection'
            
            #connection, client_address = self.sock.accept()
            name = connection.recv(16)
            
            print "Connection: ", connection
            print "Client Add: ", client_address
            
            print name, " just joined"
            self.connectionsStack.append([connection,client_address,name]) 
            print "Over Here1! + len: ", len(self.connectionsStack)
        
    def listenForMessages(self):
        while True:
            print "Over Here2! + len: ", len(self.connectionsStack)
            for conn in self.connectionsStack:
                message = conn[0].recv(16)
                print "Over Here!"
                print >>sys.stderr, conn[2],': "%s"' % data

                self.broadcastMessageOthers(message,conn)

        '''    try:
            print >>sys.stderr, 'connection from', client_address

            # Receive the data in small chunks and retransmit it
            while True:

                data = connection.recv(16)
                print >>sys.stderr, 'received "%s"' % data
                if data:
                    print >>sys.stderr, 'sending data back to the client'
                    connection.sendall(data)
                else:
                    print >>sys.stderr, 'no more data from', client_address
                    break
                
        finally:
            # Clean up the connection
            connection.close()'''

    def broadcastMessageOthers(self,connections,message,conn):
        #Broadcast message to other clients connected
        for nConn in self.connectionsStack:
            if conn[0] != nConn[0]:
                nConn[0].sendall(conn[2],": ",data)

if __name__ == '__main__':
    Server().main()