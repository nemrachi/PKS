import socket
import packetHeader as pH
import flags as flag
import sys
import threading


def receive():
    # host = "127.0.0.1" #localhost
    # port = 3003
    #
    # receiverSocket = socket.socket(socket.AF_INET,  # Internet
    #                      socket.SOCK_DGRAM)  # UDP
    # receiverSocket.bind((host, port))
    #
    # while True:
    #     data, addr = receiverSocket.recvfrom(1500)  # buffer size is 1500 bytes
    #     print("received message:", data)

    host = "127.0.0.1"  # localhost
    port = 3003

    receiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP
    try:
        receiverSocket.bind((host, port))
    except socket.error as msg:
        print("Error with bind: " + str(msg))

    receiverSocket.listen(1)  # accept only one connection
    connection, addr = receiverSocket.accept()
    print("Connection from: " + str(addr))

    while True:
        data = connection.recv(1500)
        if not data:
            break
        print("from connected  user: " + str(data))

        data = str(data).upper()
        print("Received from User: " + str(data))

        data = input(" ? ")
        connection.send(data.encode())

    connection.close()



