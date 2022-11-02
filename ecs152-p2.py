# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from pickle import FALSE, TRUE
import sys
import socket
import binascii
# import bitarray

def get_type(type):
    types = [
        "ERROR",  # type 0 does not exist
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
    AA = 0
    TC = 0
    RD = 0
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 0
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    # question
    QName = 0
    QType = 0
    QClass = 0
    # resource record:

    # answer

    ANS_name = 0
    ANS_type = 0
    ANS_class = 0
    ANS_ttl = 0
    ANS_rdlength = 0
    ANS_rddata = 0
    # authority

    AUTH_name = 0
    AUTH_type = 0
    AUTH_class = 0
    AUTH_ttl = 0
    AUTH_rdlength = 0
    AUTH_rddata = 0
    # additional

    ADD_name = 0
    ADD_type = 0
    ADD_class = 0
    ADD_ttl = 0
    ADD_rdlength = 0
    ADD_rddata = 0
    # offset
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

    message += "00"  # Terminating bit for QNAME

    # Type of request
    QTYPE = 0
    message += "{:04x}".format(QTYPE)

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)
    message += addr_parts[0].encode('utf-8').hex()
    message += "{:04x}".format(ANS_type)
    message += "{:04x}".format(ANS_class)
    message += "{:04x}".format(ANS_ttl)
    message += "{:04x}".format(ANS_rdlength)
    message += "{:04x}".format(ANS_rddata)

    message += addr_parts[0].encode('utf-8').hex()
    message += "{:04x}".format(AUTH_type)
    message += "{:04x}".format(AUTH_class)
    message += "{:04x}".format(AUTH_ttl)
    message += "{:04x}".format(AUTH_rdlength)
    message += "{:04x}".format(AUTH_rddata)

    message += addr_parts[0].encode('utf-8').hex()
    message += "{:04x}".format(ADD_type)
    message += "{:04x}".format(ADD_class)
    message += "{:04x}".format(ADD_ttl)
    message += "{:04x}".format(ADD_rdlength)
    message += "{:04x}".format(ADD_rddata)

    print(len(message))

    return message


def send_message(message):
    DNS_IP = "169.237.229.88"  # change this by country
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    client.sendto(binascii.unhexlify(message), address)

    data, address = client.recvfrom(READ_BUFFER)

    print(data)

    hex = binascii.hexlify(data)

    return hex.decode()


def parse(message):
    # header:

    response = []

    ID = message[0:4]

    flags = message[4:8]
    parameters = bin(int(flags, 16)).zfill(16)

    QR = parameters[0:1]
    OPCODE = parameters[1:5]
    AA = parameters[5:6]
    TC = parameters[6:7]
    RD = parameters[7:8]
    RA = parameters[8:9]
    Z = parameters[9:12]
    RCODE = parameters[12:16]

    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]


    header = ["ID", "QR", "OPCODE", "AA", "TC", "RD", "RA", "Z", "RCODE", "QDCOUNT", "ANCOUNT", "NSCOUNT", "ARCOUNT"]
    header_values = [ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT]

    for i in range(0, len(header)):
        response.append(header[i] + ": " + header_values[i])


    # question
    qlength = message[24:26]
    qname = ""
    qcurrent = ""

    end = 26 + int(qlength) * 2

    qname = message[26:end]

    q_string = bytes.fromhex(qname)
    q_string = q_string.decode("ascii")
    q_string = q_string

    print(q_string)
    
    start = end
    end = start + 2

    while message[start:end] != "00":
        qlength = message[start:end]
        p_end = end + int(qlength) * 2
        qname = message[end:p_end]

        qname = bytes.fromhex(qname)
        qname = qname.decode("ascii")
        q_string = q_string + "." + qname
        
        start = p_end
        end = p_end + 2

    start = p_end
    end = p_end + 4
    
    qtype = message[start:end]

    start = end
    end = end + 4

    qclass = message[start:end]

    #answer
    start = end
    end = end + 4



    aname = message[start:end]

    start = end
    end = end + 4

    atype = message[start:end]

    if atype == "0000":

        start = end
        end = end + 4

        aclass = message[start:end]

        start = end
        end = end + 8

        attl = message[start:end]

        start = end
        end = end + 4

        rdlength = message[start:end]
        print(rdlength)

        start = end
        end = end + int(rdlength) * 2

        rd = message[start:end]
        ip = ""

        count = 0
        count_end = 2

        while count != int(rdlength):
            current = rd[count:count_end]
            temp = bytes.fromhex(current)
            if count_end != int(rdlength):
                ip = ip + temp.decode("ascii") + "."

            count = count_end
            count_end = count_end + 2
        
        print(ip)



    print(q_string)
    
    # while message[tracker:tracker+2] != "00" or qlength != 0:
    #     print(tracker)
    #     for i in range(int(qlength)):
    #         if message[tracker:tracker+2] != "00": 
    #             qcurrent = qcurrent + message[tracker:tracker+2]
    #             tracker += 2
    #         else:
    #             print("reached end")
    #             break
    #     qname = bytes.fromhex(qcurrent)
    #     qname = qname.decode("ascii")
    #     qcurrent = ""
    #     if message[tracker:tracker+2] != "00": 
    #         qname = qname + "."
    #         qlength = message[tracker:tracker+2]


    



        

    


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    host = sys.argv[1]
    message = create_query(host)
    returnme = send_message(message)
    print(returnme)
    parse(returnme)
# See PyCharm help at https://www.jetbrains.com/help/pycharm/