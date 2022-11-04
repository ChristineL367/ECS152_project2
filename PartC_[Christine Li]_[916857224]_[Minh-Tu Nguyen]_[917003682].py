from pickle import FALSE, TRUE
import sys
import socket
import binascii
import time

import os.path # for creating file check

def get_type(input):
    types = ["ERROR", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTS", "HINFO", "MINFO",
             "MX", "TXT"]

    if type(input) == str:
        return "{:04x}".format(types.index(type))
    else:
        if input < 17:
            return types[input]
        elif input == 28:
            return "AAAA"


def create_query(hostname):

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

    request = ID_str + flags + QDCOUNT_str + ANCOUNT_str + NSCOUNT_str + ARCOUNT_str

    addr = hostname.split(".")
    for part in addr:
        ad_len = "{:02x}".format(len(part))
        ad_part = binascii.hexlify(part.encode())
        request += ad_len
        request += ad_part.decode()

    request += "00"  # Terminating bit for QNAME

    # Type of request
    QTYPE = 1
    QTYPE_str = "{:04x}".format(QTYPE)
    request += QTYPE_str

    # Class for lookup. 1 is Internet
    QCLASS = 1
    QCLASS_str = "{:04x}".format(QCLASS)
    request += QCLASS_str

    return request


def send_message(message, IP):
    DNS_IP = IP  # change this by root
    DNS_PORT = 53

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
    start = time.perf_counter()
    client.sendto(binascii.unhexlify(message), address)

    data, address = client.recvfrom(4096)

    client.close()
    end = time.perf_counter()
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

    # answer
    start = end
    end = end + 4
    count = [int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)]

    num_ans = max(count)

    an, an_ips, an_cache_time, an_ttl, nstart, nend = parse_rr(message, start, end, int(ANCOUNT, 16))
    ns, ns_ips, ns_cache_time, ns_ttl,nstart, nend = parse_rr(message, nstart, nend, int(NSCOUNT, 16))
    ar, ar_ips, ar_cache_time, ar_ttl, nstart, nend = parse_rr(message, nstart, nend, int(ARCOUNT, 16))

    print("AN: TTL in milliseconds:", an_cache_time, "TTL:", an_ttl)
    print("NS: TTL in milliseconds:", ns_cache_time, "TTL:", ns_ttl)
    print("AR: TTL in milliseconds:", ar_cache_time, "TTL:", ar_ttl)

    return response, an_ips + ns_ips + ar_ips

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
    ips=[]
    ttl = 0
    cache_time = 0
    for current in range(num):
        aname = message[start:end]
        atype = message[start + 4:end + 4]
        atype = get_type(int(atype, 16))
        aclass = message[start + 8:end + 8]
        ttl = message[start + 12:end + 16]

        rdlength = message[start + 20:end + 20]
        end = end + 20 + int(rdlength, 16) * 2
        rddata = message[start + 24:end]

        tracker = 0
        end_tracker = 0
        ip = ""
        ip_sec = ""

        while tracker != int(rdlength, 16) * 2:
            end_tracker = tracker + 2
            ip_sec = int(rddata[tracker:end_tracker], 16)
            if (tracker + 2 != int(rdlength, 16) * 2):
                ip = ip + str(ip_sec) + "."
            else:
                ip = ip + str(ip_sec)

            tracker += 2
            end_tracker += 2

        response_list.append("ANAME: " + aname)
        response_list.append("ATYPE: " + atype)
        response_list.append("ACLASS " + aclass)
        response_list.append("TTL: " + str(ttl))


        response_list.append("RDLENGTH: " + str(int(rdlength, 16)))
        response_list.append("RDDATA: " + rddata)
        response_list.append("IP: " + ip)
        ips.append(ip)
        response_list.append("")

        start = end
        end = end + 4
        ttl_hex = binascii.unhexlify(ttl)
        cache_time = int(''.join(format(x, '02x') for x in ttl_hex), 16)
    return response_list, ips, cache_time, ttl, start, end

# format: domain type ip
def check_cache(domain, type):
    ip = ""
    mark = FALSE
    phrase = domain + " " + type
    if os.path.exists("partc_cache.txt"):
        with open('partc.txt') as file:
            if phrase in file.read():
                mark = TRUE

    if mark:
        with open('partc_cache.txt', 'r') as file:
            for index, line in enumerate(f):
                if phrase in line:
                    ip = line        
                    break
        
        if ip != "":
            ph_len = len(phrase)
            ip = ip[ph_len+1:]
                
    return mark, ip

def make_cache():
    if os.path.exists("partc.txt") == FALSE:
        html_file = open("partc,txt","w")
        html_file.writelines(input)
        html_file.close()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    host = ["youtube.com", "facebook.com","tmz.com", "cnn.com", "nytimes.com"]
    for k in host:
        print(k)
        message = create_query(k)
        print("Root IP:", "199.7.83.42")
        response_Root, t1 = send_message(message, "199.7.83.42")

        response_Root, ips = parse(response_Root)

        tld_ip = ips[0]
        for i in ips:
            if len(i) < 16:
                tld_ip=i

        print("TLD IP:", tld_ip)
        response_TLD, t2 = send_message(message, tld_ip)

        response_TLD, ips = parse(response_TLD)

        auth_ip = ips[0]
        for i in ips:
            if len(i) < 16:
                auth_ip = i
        print("Auth IP:", auth_ip)
        response_Auth, t3 = send_message(message, auth_ip)
        print("RTT to resolve hostname", t1 + t2+t3)
        response_Auth, ips = parse(response_Auth)

        resolved_ip = ips[0]
        for j in ips:
            if len(j) < 16:
                resolved_ip = j
                print("Resolved IP for", k+":", resolved_ip)
                break
        print("\n")