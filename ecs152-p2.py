# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import sys
import socket

import binascii
def get_type(type):
    types = [
        "ERROR", # type 0 does not exist
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]
def create_query(hostname):
   
    ID = 43690
    QR = 0
    OPCODE = 0
    AA=0
    TC= 0
    RD= 0
    RA =0
    Z=0
    RCODE=0
    QDCOUNT=0
    ANCOUNT=0
    NSCOUNT=0
    ARCOUNT=0
    #question 
    QName=0
    QType=0
    QClass=0
    #resource record:
    
    #answer
        
    ANS_name = 0
    ANS_type = 0
    ANS_class = 0
    ANS_ttl = 0
    ANS_rdlength = 0
    ANS_rddata = 0
    #authority
        
    AUTH_name = 0
    AUTH_type = 0
    AUTH_class = 0
    AUTH_ttl = 0
    AUTH_rdlength = 0
    AUTH_rddata = 0
        #additional
       
    ADD_name = 0
    ADD_type = 0
    ADD_class = 0
    ADD_ttl = 0
    ADD_rdlength = 0
    ADD_rddata = 0
        #offset
    OFFSET = 0
    
    message = ""
    
    query = str(QR)
    query += str(OPCODE).zfill(4)
    query += str(AA) + str(TC) + str(RD) + str(RA)
    query += str(Z).zfill(3)
    query += str(RCODE).zfill(4)
    
    query = "{:04x}".format(int(query, 2))
    message += "{:04x}".format(ID)
    message += query
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    addr_parts = hostname.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00" # Terminating bit for QNAME

    # Type of request
    QTYPE = 0
    message += "{:04x}".format(QTYPE)

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)
    message+= "{:04x}".format(0)
    message+= "{:04x}".format(ANS_type)
    message+= "{:04x}".format(ANS_class)
    message+= "{:04x}".format(ANS_ttl)
    message+= "{:04x}".format(ANS_rdlength)
    message+= "{:04x}".format(ANS_rddata)
    
    message+="{:04x}".format(0)
    message+= "{:04x}".format(AUTH_type)
    message+= "{:04x}".format(AUTH_class)
    message+= "{:04x}".format(AUTH_ttl)
    message+= "{:04x}".format(AUTH_rdlength)
    message+= "{:04x}".format(AUTH_rddata)

    message+= "{:04x}".format(0)
    message+= "{:04x}".format(ADD_type)
    message+= "{:04x}".format(ADD_class)
    message+= "{:04x}".format(ADD_ttl)
    message+= "{:04x}".format(ADD_rdlength)
    message+= "{:04x}".format(ADD_rddata)
    DNS_IP = "169.237.229.88" #change this by country
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    client.sendto(binascii.unhexlify(message), address)

    data, address = client.recvfrom(READ_BUFFER)



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    host = sys.argv[1]
    create_query(host)
# See PyCharm help at https://www.jetbrains.com/help/pycharm/