from pickle import FALSE, TRUE
import sys
import socket
import binascii
import time

import os.path  # for creating file check

cache_dictionary = {}
prompting = 0
def get_type(input):
    #gets the type of the query
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
    #create a query using custom values for each field
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

    RD = 0
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
    #send a message using UDP socket calls
    DNS_IP = IP  # change this by root
    DNS_PORT = 53 

    READ_BUFFER = 1024  # The size of the buffer to read in the received UDP packet.

    address = (DNS_IP, DNS_PORT)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Internet, UDP.
    start = time.perf_counter() #count the time we started sending the message
    client.sendto(binascii.unhexlify(message), address)

    data, address = client.recvfrom(4096)

    client.close()
    end = time.perf_counter() #the time we got the message back and closed the connection
    hex = binascii.hexlify(data)

    return hex.decode("utf-8"), (end - start) * 1000 


def parse(message):
    #parse the message we got back from the server we queried
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
    # we get the name, a dictionary that maps ip to cache time, the ttl as time, the ttl, and a start and end valuw
    an, an_ips, an_cache_time, an_ttl, nstart, nend = parse_rr(message, start, end, int(ANCOUNT, 16))
    ns, ns_ips, ns_cache_time, ns_ttl, nstart, nend = parse_rr(message, nstart, nend, int(NSCOUNT, 16))
    ar, ar_ips, ar_cache_time, ar_ttl, nstart, nend = parse_rr(message, nstart, nend, int(ARCOUNT, 16))
    if prompting == 0:
        print("AN: TTL in milliseconds:", an_cache_time, "TTL:", an_ttl)
        print("NS: TTL in milliseconds:", ns_cache_time, "TTL:", ns_ttl)
        print("AR: TTL in milliseconds:", ar_cache_time, "TTL:", ar_ttl)
    all_ips = {**an_ips, **ns_ips, **ar_ips}
    return response, all_ips


def parse_rr(message, start, end, num):
    #parsing each resource record
    response_list = []
    ips = {}
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
        ttl_hex = binascii.unhexlify(ttl)
        cache_time = int(''.join(format(x, '02x') for x in ttl_hex), 16)
        ips[ip] = cache_time
        response_list.append("")

        start = end
        end = end + 4

    return response_list, ips, cache_time, ttl, start, end


def add_cache(ip, ttl, hostname, layer):
    # create a cache dictionary of the following format:
    # dict = {hostname: [{TLD: [{ip: [ttl, time]}, {ip2:[ttl,time]}]}, {auth: [{ip: [ttl, time]}]}]}
    if hostname not in cache_dictionary:
        cache_dictionary[hostname] = []

    if len(cache_dictionary[hostname]) == 0:

        cache_dictionary[hostname].append({layer: []})
    present = 0
    for i in cache_dictionary[hostname]:
        if layer in i:
            present = 1
            break
    if present == 0:
        cache_dictionary[hostname].append({layer: []})

    if layer == "TLD":

        if len(i) < 16:
            cache_dictionary[hostname][0][layer].append({ip: [ttl, time.perf_counter()*1000]})
    elif layer == "Auth":

        if len(i) < 16:
            cache_dictionary[hostname][1][layer].append({ip: [ttl, time.perf_counter()*1000]})

    elif layer == "Resolved":

        if len(i) < 16:
            cache_dictionary[hostname][2][layer].append({ip: [ttl, time.perf_counter()*1000]})


def check_cache(hostname, layer):
    # check if the hostname is in the cache and that specific "layer", if so, check if it is expired.
    t1 = time.perf_counter()*1000
    get_ip = ""
    in_dict = False

    if hostname in cache_dictionary:

        for l in range(len(cache_dictionary[hostname])):
            if layer in cache_dictionary[hostname][l]:
                # print(time_dictionary[hostname][type])
                ip_items = cache_dictionary[hostname][l][layer][0].items()

                for key, value in (ip_items):  # key: ip value: time list

                    if (t1 - value[1] > value[0]):
                        #remove the item from the dictionary if the ttl is expired.
                        remove_cache(hostname, layer, l)
                        return get_ip, in_dict
                    else:
                        # otherwise, the ip is the cached ip.
                        get_ip = key
                        in_dict = True
                        return get_ip, in_dict
        else:
            print("no layer found")
            return get_ip, in_dict

    else:
        print("no hostname found")
        return get_ip, in_dict
    pass


def remove_cache(hostname, layer, l):
    if (len(cache_dictionary[hostname])) == 1:
        del cache_dictionary[hostname]
    else:
        del (cache_dictionary[hostname][l])
    pass


if __name__ == '__main__':
    host = ["youtube.com", "facebook.com", "tmz.com", "cnn.com", "nytimes.com"]
    messages = {}
    #RUNNING ALL WEBSITES WITHOUT CACHE
    for k in host:  # dictionary format: dict = {hostname: [{TLD: [{ip: [ttl, time]}, {ip2:[ttl,time]}]}, {auth: [{ip: [ttl, time]}]}
        print(k)
        message = create_query(k)
        messages[k] = message
        
        #send message to root to get the TLD IPs
        print("Root IP:", "199.7.83.42")
        response_Root, t1 = send_message(message, "199.7.83.42")

        response_Root, ips = parse(response_Root)
        #within TLD ips, select one with a length shorter than 16 so we exclude IPv6
        tld_ip = list(ips.keys())[0]
        tld_ttl = ips[tld_ip]
        for i in list(ips.keys()):
            if len(i) < 16:
                tld_ip = i
                tld_ttl = ips[tld_ip]
        add_cache(tld_ip, tld_ttl, k, "TLD")

        print("TLD IP:", tld_ip)
        #send message to chosen TLD ip to get Auth IPs
        response_TLD, t2 = send_message(message, tld_ip)

        response_TLD, ips = parse(response_TLD)
         #within Auth ips, select one with a length shorter than 16 so we exclude IPv6
        auth_ip = list(ips.keys())[0]
        auth_ttl = ips[auth_ip]
        for i in list(ips.keys()):
            if len(i) < 16:
                auth_ip = i
                auth_ttl = ips[auth_ip]
        add_cache(auth_ip, auth_ttl, k, "Auth")
        print("Auth IP:", auth_ip)
        #send message to Auth IP to get resolved IP
        response_Auth, t3 = send_message(message, auth_ip)


        response_Auth, ips = parse(response_Auth)
        #within resolved IPs, exclude IPv6 and choose an IPv4
        resolved_ip = list(ips.keys())[0]
        resolved_ttl = ips[resolved_ip]
        for i in list(ips.keys()):
            if len(i) < 16:
                resolved_ip = i
                print("Resolved IP for", k + ":", resolved_ip)
                resolved_ttl = ips[resolved_ip]
                break
        add_cache(resolved_ip, resolved_ttl, k, "Resolved")
        print("RTT to resolve hostname", t1 + t2 + t3)
        print("\n")

    prompt = True
    print("PROMPT USER FOR INPUT WITH A CACHE FROM OUR PREVIOUS RUN, ONLY THE 5 GIVEN DOMAINS ARE VALID INPUTS")
    prompting = 1
    while prompt:
        #   dict = {hostname: [{TLD: [{ip: [ttl, time]}, {ip2:[ttl,time]}]}, {auth: [{ip: [ttl, time]}]}]}
        hostname = input("Enter hostname:")
        if hostname not in ["tmz.com", "facebook.com", "cnn.com", "nytimes.com", "youtube.com"]:
            #exit if the input isn't a valid hostname
            prompt = False
            break
        start = time.perf_counter() #time we started to count for getting the resolved IP back
        try:
            #check first if the resolved ip is already in the cache and return if so
            resolved = 0
            for i in list(cache_dictionary[hostname][2]["Resolved"][0].keys()):
                ip, cached = check_cache(hostname, "Resolved")

                if cached:

                    resolved = ip
                else:
                    #purposely create an error to exit to the exception clause
                    print(2/0)
            #time we stop counting for getting the resolved ip in the case it is in the cache
            end = (time.perf_counter() - start) * 1000
            #time we stop counting for 
            print("RESOLVED IP:", resolved,'\n'+ "RTT to resolve hostname:",end)

        except:
            #check layer by layer (root, dns, auth, resolved) if their ip is cached
            #check if tld is cached
            tld = cache_dictionary[hostname][0]["TLD"][0]
            auth_check = 1
            resolve_check = 2
            ip_addr = 0
            TLD_IP = 0
            if tld != []:
                for i in list(tld.keys()):
                    ip, cached = check_cache(hostname, "TLD")
                    if cached:
                        TLD_IP = ip

            if TLD_IP == 0:
                 #if tld is not cached, send message to root to find it
                auth_check -=1 #decrement the index we check for auth ip since tld is not cached
                resolve_check -=1 #decrement the index we check for resolved ip since auth is not cached
                response_Root, t1 = send_message(messages[hostname], "199.7.83.42")

                response_Root, ips = parse(response_Root)
                TLD_IP = list(ips.keys())[0]
                for i in list(ips.keys()):
                    if len(i) < 16:
                        TLD_IP = i
            print("TLD_IP:", TLD_IP)
            auth = cache_dictionary[hostname][auth_check]["Auth"][0]
            #check if auth is cached
            ip_addr = 0
            AUTH_IP = 0
            if auth != []:
                for i in list(auth.keys()):
                    ip, cached = check_cache(hostname, "Auth")
                    if cached:
                        AUTH_IP = i
                if AUTH_IP != 0:
                    #if auth is cached, use it to find resolved IP by sending a signal to the cached Auth
                    print("AUTH_IP:", AUTH_IP)
                    response_Auth, t3 = send_message(messages[hostname], AUTH_IP)


                    response_Auth, ips = parse(response_Auth)

                    resolved_ip = list(ips.keys())[0]
                    resolved_ttl = ips[resolved_ip]
                    for i in list(ips.keys()):
                        if len(i) < 16:
                            resolved_ip = i
                            #time we stop counting for getting the resolved ip in the case it isn't in the cache 
                            end = (time.perf_counter() - start) * 1000
                            print("RESOLVED IP:", resolved_ip,'\n'+ "RTT to resolve hostname:", end)

                            resolved_ttl = ips[resolved_ip]
                            break
                elif AUTH_IP == 0:
                    # if auth not cached, send message to the tld server we found and then use the auth ip it returns to query for the resolved ip
                    resolve_check -=1 #decrement the index we check for resolved ip since auth is not cached
                    response_TLD, t2 = send_message(messages[hostname], TLD_IP)

                    response_TLD, ips = parse(response_TLD)
                    AUTH_IP = list(ips.keys())[0]
                    for i in list(ips.keys()):
                        if len(i) < 16:
                            AUTH_IP = i
                    response_Auth, t3 = send_message(messages[hostname], AUTH_IP)
                    print("AUTH IP: ", AUTH_IP)

                    response_Auth, ips = parse(response_Auth)

                    resolved_ip = list(ips.keys())[0]
                    resolved_ttl = ips[resolved_ip]
                    for i in list(ips.keys()):
                        if len(i) < 16:
                            resolved_ip = i
                            #time we stop counting for getting the resolved ip in the case it isn't in the cache 
                            end = (time.perf_counter() - start) * 1000
                            
                            print("RESOLVED IP:", resolved_ip, '\n'+"RTT to resolve hostname:", end)
                            resolved_ttl = ips[resolved_ip]
                            break


        print("\n")
