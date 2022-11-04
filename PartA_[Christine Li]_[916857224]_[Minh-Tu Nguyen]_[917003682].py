from pickle import FALSE, TRUE
import sys
import socket
import binascii
import time

import os.path # for creating file check


def create_query(hostname):

    # header components: content + changed to string
    ID = 22222
    ID_str = "{:04x}".format(ID)
    
    QR = 0
    QR_str = str(QR)

    OPCODE = 0
    OPCODE_str = str(OPCODE).zfill(4)
    AA = 0
    AA_str = str(AA)

    TC = 0
    TC_str = str(TC)

    RD = 1
    RD_str = str(RD)

    RA = 0
    RA_str = str(RA)

    Z = 0
    Z_str = str(Z).zfill(3)

    RCODE = 0
    RCODE_str = str(RCODE).zfill(4)

    flags = QR_str + OPCODE_str + AA_str + TC_str + RD_str + RA_str + Z_str + RCODE_str
    flags = "{:04x}".format(int(flags, 2))

    QDCOUNT = 1
    QDCOUNT_str = "{:04x}".format(QDCOUNT)

    ANCOUNT = 0
    ANCOUNT_str = "{:04x}".format(ANCOUNT)
    
    NSCOUNT = 0
    NSCOUNT_str = "{:04x}".format(NSCOUNT)

    ARCOUNT = 0
    ARCOUNT_str = "{:04x}".format(ARCOUNT)

    request = ID_str + flags + QDCOUNT_str + ANCOUNT_str + NSCOUNT_str + ARCOUNT_str

    # question:
    # break down hostname
    addr = hostname.split(".")
    for part in addr:
        # length of part
        ad_len = "{:02x}".format(len(part))
        # conent of part
        ad_part = binascii.hexlify(part.encode())

        request += ad_len
        request += ad_part.decode()

    # terminate qname (domain name) component
    request += "00" 

    # type of question
    QTYPE = 1
    QTYPE_str = "{:04x}".format(QTYPE)
    request += QTYPE_str

    # question class
    QCLASS = 1
    QCLASS_str = "{:04x}".format(QCLASS)
    request += QCLASS_str


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

    # request string

    return request

# get type of response
def get_type(input):
    types = ["ERROR", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTS", "HINFO", "MINFO", "MX", "TXT"]

    if type(input) == str:
        return "{:04x}".format(types.index(type))
    else:
        return types[int(input,16)]

# sending message to DNS IP
def send_message(message):
    DNS_IP = "169.237.229.88"  # change this by country
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.

    # send message to give address
    start = time.perf_counter()
    client.sendto(binascii.unhexlify(message), address)

    # receive message
    data, address = client.recvfrom(4096)
    end = time.perf_counter()

    client.close()

    # decode received message
    hex = binascii.hexlify(data)

    return hex.decode("utf-8"), (end-start) * 1000


def parse(message):

    # header:
    response = []

    ID = message[0:4]

    flags = message[4:8]
    parameters = format(int(flags, 16), "b").zfill(16)

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

    end = 26 + int(qlength, 16) * 2

    qname = message[26:end]

    q_string = bytes.fromhex(qname)
    q_string = q_string.decode("ascii")
    q_string = q_string
    
    start = end
    end = start + 2

    # parse the domain name of question until reach terminating value
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

    #answer
    start = end
    end = end + 4

    # track ip addresses found
    ip_list = []

    # loop through answer resource records
    for current in range(int(ANCOUNT, 16)):
        aname = message[start:end]
        atype = message[start+4:end+4]
        aclass = message[start+8:end+8]
        ttl = message[start+12:end+16]
        rdlength = message[start+20:end+20]
        end = end + 20 + int(rdlength, 16)*2
        rddata = message[start+24:end]

        tracker = 0
        end_tracker = 0
        ip = ""
        ip_sec = ""

        # break down A answer IP address
        if atype == "0001":
            while tracker != int(rdlength,16)*2:
                end_tracker = tracker + 2
                ip_sec = int(rddata[tracker:end_tracker], 16)
                if(tracker + 2 != int(rdlength,16)*2):
                    ip = ip + str(ip_sec) + "."
                else:
                    ip = ip + str(ip_sec)
                
                
                tracker += 2
                end_tracker += 2

            
            
            response.append("ANAME: " + aname)
            response.append("ATYPE: " + atype)
            response.append("ACLASS " + aclass)
            response.append("TTL: " + str(ttl))
            response.append("RDLENGTH " + str(int(rdlength,16)))
            response.append("RDDATA: " + rddata)
            response.append("IP: " + ip)
            ip_list.append(ip)
        
        start = end
        end = end + 4
                
    return q_string, ip_list

# send HTTP get request to found IP Address
def connection(domain, ip):
    target_host = domain
 
    target_port = 80  # create a socket object 
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    
    # connect the client 
    start = time.perf_counter()
    client.connect((ip, target_port))  
    
    # send some data 
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % target_host
    client.send(request.encode())  
    
    # receive some data 
    response = client.recv(4096)  
    end = time.perf_counter()

    http_response = repr(response)
    http_response_len = len(http_response)

    # change response to a string
    content = str(response, 'utf-8')
    return content, (end-start) * 1000
    
# write 
def write_html(content):
    if os.path.exists("Parta_http_[Christine Li]_[916857224]_[Minh-Tu Nguyen]_[917003682].txt"):
        html_file = open("Parta_http_[Christine Li]_[916857224]_[Minh-Tu Nguyen]_[917003682].txt","a")
    else: 
        html_file = open("Parta_http_[Christine Li]_[916857224]_[Minh-Tu Nguyen]_[917003682].txt","w")

    input = ["USA: \n", content , "\n\n" ]

    html_file.writelines(input)
    html_file.close()

    
if __name__ == '__main__':
    host = sys.argv[1]
    message = create_query(host)
    response, resolver_time = send_message(message)
    domain, ip = parse(response)

    content, http_time = connection(domain, ip[0])

    # print("Resolver: ", resolver_time)
    # print("HTTP: ", http_time)
    # write_html(content)

    print("Domain: " + domain)
    print("HTTP Server Address: " + ip[0])
