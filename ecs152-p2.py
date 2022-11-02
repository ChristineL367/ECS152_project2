from pickle import FALSE, TRUE
import sys
import socket
import binascii

def get_type(input):
    types = ["ERROR", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTS", "HINFO", "MINFO", "MX", "TXT"]

    if type(input) == str:
        return "{:04x}".format(types.index(type))
    else:
        if input < 17:
            return types[input]
        elif input == 28:
            return "AAAA"



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
    QDCOUNT = 1
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
    QTYPE = 1
    message += "{:04x}".format(QTYPE)

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)
    # message += addr_parts[0].encode('utf-8').hex()
    # message += "{:04x}".format(ANS_type)
    # message += "{:04x}".format(ANS_class)
    # message += "{:04x}".format(ANS_ttl)
    # message += "{:04x}".format(ANS_rdlength)
    # message += "{:04x}".format(ANS_rddata)

    # message += addr_parts[0].encode('utf-8').hex()
    # message += "{:04x}".format(AUTH_type)
    # message += "{:04x}".format(AUTH_class)
    # message += "{:04x}".format(AUTH_ttl)
    # message += "{:04x}".format(AUTH_rdlength)
    # message += "{:04x}".format(AUTH_rddata)

    # message += addr_parts[0].encode('utf-8').hex()
    # message += "{:04x}".format(ADD_type)
    # message += "{:04x}".format(ADD_class)
    # message += "{:04x}".format(ADD_ttl)
    # message += "{:04x}".format(ADD_rdlength)
    # message += "{:04x}".format(ADD_rddata)


    return message


def send_message(message):
    DNS_IP = "192.33.4.12"  # change this by country
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    client.sendto(binascii.unhexlify(message), address)

    data, address = client.recvfrom(4096)

    client.close()

    hex = binascii.hexlify(data)

    return hex.decode("utf-8")


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

    response.append("")
    # question
    qlength = message[24:26]
    qname = ""
    qcurrent = ""

    end = 26 + int(qlength, 16) * 2

    qname = message[26:end]

    q_string = bytes.fromhex(qname)
    q_string = q_string.decode("ascii")
    q_string = q_string
    
    start = end
    end = start + 2

    while message[start:end] != "00":
        qlength = message[start:end]
        p_end = end + int(qlength, 16) * 2
        qname = message[end:p_end]

        qname = bytes.fromhex(qname)
        qname = qname.decode("ascii")
        q_string = q_string + "." + qname
        
        start = p_end
        end = p_end + 2
    
    response.append("Domain: " + q_string)

    start = p_end + 4
    end = p_end + 6
    
    qtype = message[start:end]

    response.append("QTYPE: " + qtype)

    start = end
    end = end + 4

    qclass = message[start:end]

    response.append("QCLASS: " + qclass)

    response.append("")

    #answer
    start = end
    end = end + 4
    count = [int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)]

    num_ans = max(count)

    an, nstart, nend = parse_rr(message, start, end, int(ANCOUNT, 16))
    ns, nstart, nend = parse_rr(message, nstart, nend, int(NSCOUNT, 16))
    ar, nstart, nend = parse_rr(message, nstart, nend, int(ARCOUNT, 16))

    
    print(*response, sep = "\n")
    print(*an, sep = "\n")
    print(*ns, sep = "\n")
    print(*ar, sep = "\n")
    


# def connection(domain, ip):
#     target_host = "domain" 
 
#     target_port = 80  # create a socket object 
#     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    
#     # connect the client 
#     client.connect(("157.240.22.35",target_port))  
    
#     # send some data 
#     request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % target_host
#     client.send(request.encode())  
    
#     # receive some data 
#     response = client.recv(4096)  
#     http_response = repr(response)
#     http_response_len = len(http_response)

#     print(str(response, 'utf-8'))
    

def parse_rr(message, start, end, num):

    response_list = []

    for current in range(num):
        aname = message[start:end]
        atype = message[start+4:end+4]
        atype = get_type(int(atype, 16))
        aclass = message[start+8:end+8]
        ttl = message[start+12:end+16]
        rdlength = message[start+20:end+20]
        end = end + 20 + int(rdlength, 16)*2
        rddata = message[start+24:end]

        tracker = 0
        end_tracker = 0
        ip = ""
        ip_sec = ""


        while tracker != int(rdlength,16)*2:
            end_tracker = tracker + 2
            ip_sec = int(rddata[tracker:end_tracker], 16)
            if(tracker + 2 != int(rdlength,16)*2):
                ip = ip + str(ip_sec) + "."
            else:
                ip = ip + str(ip_sec)
            
            
            tracker += 2
            end_tracker += 2
        
        response_list.append("ANAME: " + aname)
        response_list.append("ATYPE: " + atype)
        response_list.append("ACLASS " + aclass)
        response_list.append("TTL: " + str(ttl))
        response_list.append("RDLENGTH: " + str(int(rdlength,16)))
        response_list.append("RDDATA: " + rddata)
        response_list.append("IP: " + ip)
        response_list.append("")
        
        start = end
        end = end + 4
    
    return response_list, start, end

    


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    host = sys.argv[1]
    message = create_query(host)
    response = send_message(message)
    # print(response)
    response = parse(response)
    # response = display(response)