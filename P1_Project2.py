# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import sys
import socket
def create_query():
    DNS_QUERY = {
        'header':{
        'id': 0,
        'qr': 0,
        'opcode': 0000,
        'aa':0,
        'tc':0,
        'rd':0,
        'ra':0,
        'z':0,
        'rcode':0,
        'qdcount':0,
        'ancount':0,
        'nscount':0,
        'arcount':0},
        'question':{
            'qname': 0,
            'qtype': 0,
            'qclass': 0,
        },
        'answer':{
            'name':0,
            'type':0,
            'class':0,
            'ttl':0,
            'rdlength':0,
            'rdata':0
        },
        'authority': {
            'name': 0,
            'type': 0,
            'class': 0,
            'ttl': 0,
            'rdlength': 0,
            'rdata': 0
        },
        'additional': {
            'name': 0,
            'type': 0,
            'class': 0,
            'ttl': 0,
            'rdlength': 0,
            'rdata': 0
        },
        'offset':0
    }

    DNS_IP = "91.245.229.1" #change this by country
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    client.sendto(DNS_QUERY.tobytes(), address)

    data, address = client.recvfrom(READ_BUFFER)



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    host = sys.argv[1]
    
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
