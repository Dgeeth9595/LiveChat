# Python program to implement server side of chat room.  
import socket  
import select  
import sys  
from thread import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import pickle
import os

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
#if len(sys.argv) != 3:  
#    print ("Correct usage: script, IP address, port number") 
#    exit()  
#IP_address = str(sys.argv[1])  
#Port = int(sys.argv[2])  
IP_address = "127.0.0.1"
Port = 8777

#DUDE -> Add MTLS Secure SOCKET Creation. 
server.connect((IP_address, Port))  
name = raw_input("Name: ")
server.send(name)

#Generate DC Public and Private Key for Key Exchange
parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()

client_public_key_pem = client_public_key.public_bytes( encoding=serialization.Encoding.PEM,  format=serialization.PublicFormat.SubjectPublicKeyInfo )
print ("Client: "+client_public_key_pem)
server.send(client_public_key_pem)

server_public_key_pem = server.recv(2048) 
print ("Server Len: ", len(server_public_key_pem))
print ("Server Type: ", type(server_public_key_pem))
print ("Server: "+ server_public_key_pem) 
#server_public_key = load_pem_public_key(server_public_key_pem)
#print ("Server: "+ server_public_key) 
#Generate DC Public and Private Key for Key Exchange

#2a. DH Key Exchange -> shared_key


while True:  
  
    # maintains a list of possible input streams  
    sockets_list = [sys.stdin, server]  
  
    """ There are two possible input situations. Either the  
    user wants to give manual input to send to other people,  
    or the server is sending a message to be printed on the  
    screen. Select returns from sockets_list, the stream that  
    is reader for input. So for example, if the server wants  
    to send a message, then the if condition will hold true  
    below.If the user wants to send a message, the else  
    condition will evaluate as true"""
    read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])  
  
    for socks in read_sockets:  
        if socks == server:  
            #6. AES Decyrption w shared_key for client
            message = socks.recv(2048)  
            print (message)  
        else:  
            message = sys.stdin.readline()  
            #3. AES encryption with the shared_key
            server.send(message)  
            sys.stdout.write("You: ")  
            sys.stdout.write(message)  
            sys.stdout.flush()  
server.close()