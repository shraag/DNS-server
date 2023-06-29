# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
import binascii
import socket
import time
import sys

#The following function will create the message when given a hostname(url).
#The message is first created using hex form then convert to binary form at the end and ready to send
def message(url):

    ID = "aaaa"

    QR = "0"
    OPCODE = "{:04x}".format(0)
    AA = "0"
    TC = "0"
    RD = "1"
    RA = "0"
    Z = "{:03x}".format(0)
    RCODE = "{:04x}".format(0)

    query_parameters = "{:04x}".format(int(QR + OPCODE + AA + TC + RD + RA + Z + RCODE, 2))

    QDCOUNT = "{:04x}".format(1)
    ANCOUNT = "{:04x}".format(0)
    NSCOUNT = "{:04x}".format(0)
    ARCOUNT = "{:04x}".format(0)

    # Question Section
    url_encoded = ""
    url_sections = url.split(".")
    for section in url_sections:
        section_len = "{:02x}".format(len(section))
        section_hex = binascii.hexlify(section.encode()).decode()
        url_encoded += section_len
        url_encoded += section_hex

    url_encoded += "00"

    QTYPE = "{:04x}".format(1)
    QCLASS = "{:04x}".format(1)

    message_hex = ID + query_parameters + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT + url_encoded + QTYPE + QCLASS

    return binascii.unhexlify(message_hex)



#The following function send and receive the message UDP port 53
def send_message(message, address, port = 53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message, (address, port))
        data, _ = sock.recvfrom(1024)
    finally:
        sock.close()
    return data


# this message parses the message from DNS server
def response_unpack(data):

    head = binascii.hexlify(data[0:12]).decode("utf-8")
    ans = int(head[12:16], 16)
    numauth = int(head[16:20], 16)
    numadd = int(head[20:24], 16)


    i = 12
    question = ""

    while binascii.hexlify(data[i:i+1]).decode("utf-8") != "00":
        question += binascii.hexlify(data[i:i+1]).decode("utf-8")
        i += 1

    i += 1

    message_qtype = binascii.hexlify(data[i:i+2]).decode("utf-8")
    message_qclass = binascii.hexlify(data[i+2:i+4]).decode("utf-8")


    question_section = [question, message_qtype, message_qclass]

    i += 4

    answers = {}
    for k in range(0, ans):
        current_answer = ""

        answer_name = binascii.hexlify(data[i:i+2]).decode("utf-8")

        answer_name = format(int(answer_name, 16), 'b')
        answer_name = int(answer_name[2:], 2)
        answer_type = binascii.hexlify(data[i+2:i+4]).decode("utf-8")
        answer_class = binascii.hexlify(data[i+4:i+6]).decode("utf-8")
        answer_ttl = int(binascii.hexlify(data[i+8:i+10]).decode("utf-8"), 16)
        answer_rdlength = int(binascii.hexlify(data[i+10:i+12]).decode("utf-8"), 16)

        i += 12

        current_answer += binascii.hexlify(data[i:i+answer_rdlength]).decode("utf-8")

        ip = ""
        for c in range(0, 8, 2):
            ip += str(int(current_answer[c:c+2], 16))
            if c != 6:
                ip += '.'


        index = answer_name
        hname = ""

        while binascii.hexlify(data[index:index+1]).decode("utf-8") != "00":

            length = int(binascii.hexlify(data[index: index+1]).decode("utf-8"), 16)
            index += 1

            for c in range(0, length, 1):
                hname += chr(int(binascii.hexlify(data[index + c: index + c + 1]).decode("utf-8"), 16))
            index += length
            hname += "."


        i += answer_rdlength


        answers[ip] = [hname, answer_type, answer_class, answer_ttl]


    authority = {}
    for k in range(0, numauth):

        rr_name = binascii.hexlify(data[i:i+2]).decode("utf-8")
        rr_name = format(int(rr_name, 16), 'b')
        rr_name = int(rr_name[2:], 2)
        rr_type = binascii.hexlify(data[i+2:i+4]).decode("utf-8")
        rr_class = binascii.hexlify(data[i+4:i+6]).decode("utf-8")
        rr_ttl = int(binascii.hexlify(data[i+8:i+10]).decode("utf-8"), 16)
        rr_rdlength = int(binascii.hexlify(data[i+10:i+12]).decode("utf-8"), 16)
        i += 12


        current_answer = getHost(data, i)
        i += rr_rdlength

        index = rr_name
        hostname = getHost(data, index)

        authority[current_answer] = [hostname, rr_type, rr_class, rr_ttl]

    additional = {}
    for k in range(0, numadd):
        current_answer = ""
        rr_name = binascii.hexlify(data[i:i+2]).decode("utf-8")
        rr_name = format(int(rr_name, 16), 'b')
        rr_name = int(rr_name[2:], 2)
        rr_type = binascii.hexlify(data[i+2:i+4]).decode("utf-8")
        rr_class = binascii.hexlify(data[i+4:i+6]).decode("utf-8")
        rr_ttl = int(binascii.hexlify(data[i+8:i+10]).decode("utf-8"), 16)
        rr_rdlength = int(binascii.hexlify(data[i+10:i+12]).decode("utf-8"), 16)
        i += 12

        current_answer += binascii.hexlify(data[i:i+rr_rdlength]).decode("utf-8")
        ip = ""
        for c in range(0, 8, 2):
            ip += str(int(current_answer[c:c+2], 16))
            if c != 6:
                ip += '.'


        index = rr_name

        hname = getHost(data, index)

        i += rr_rdlength

        if rr_type == "001c":
            continue


        additional[ip] = [hname, rr_type, rr_class, rr_ttl]

    return question_section, answers, authority, additional


# this function finds the hostname by parsing the message from a particular index
def getHost(data, start_idx):
    index = start_idx
    hname = ""


    while binascii.hexlify(data[index:index+1]).decode("utf-8") != "00":

        if(binascii.hexlify(data[index:index+1]).decode("utf-8") == "c0"):

            name_start = int((binascii.hexlify(data[index+1:index+2]).decode("utf-8")), 16)

            hname += getHost(data, name_start)
            break

        length = int(binascii.hexlify(data[index: index+1]).decode("utf-8"), 16)
        index += 1

        for c in range(0, length, 1):
            hname += chr(int(binascii.hexlify(data[index + c: index + c + 1]).decode("utf-8"), 16))
        index += length
        hname += "."
    return hname


# function to get the ip addresses and going through the hierarchy of DNS
def ip_hostname(hostname):
    # list of root ips
    print("Domain:", hostname)
    root_server = ["202.12.27.33", "199.7.83.42", "193.0.14.129", "192.58.128.30", "192.36.148.17", "198.97.190.53", "192.112.36.4", "192.5.5.241", "192.203.230", "199.7.91.13", "192.33.4.12", "199.9.14.201", "198.41.0.4"]

    #root name server
    for i in root_server:
        initial_time = time.time()
        root_result = send_message(message(hostname), i)
        ending_time = time.time()
        elapsed_time1 = str(ending_time - initial_time)

        print("Root server IP address:", i)
        #print("Time to root name server:", elapsed_time1)
        break

    #TLD name server
    questions, answers, auth, add = response_unpack(root_result)
    initial_time = time.time()
    tld_result = send_message(message(hostname), list(add.keys())[0])
    ending_time = time.time()
    elapsed_time2 = str(ending_time - initial_time)

    print("TLD server  IP address:", list(add.keys())[0])
    #print("Time to TLD name server:", elapsed_time2)

    #auth name server
    questions, answers, auth, add = response_unpack(tld_result)
    initial_time = time.time()
    auth_result = send_message(message(hostname), list(add.keys())[0])
    ending_time = time.time()
    elapsed_time3 = str(ending_time - initial_time)

    print("Authoritative server  IP address:", list(add.keys())[0])
    #print("Time to authoritative name server:", elapsed_time3)

    questions, answers, auth, add = response_unpack(auth_result)
    print("HTTP Server IP address:", list(answers.keys())[0])

    #print("Total time:", float(elapsed_time1)+float(elapsed_time2)+float(elapsed_time3))


if __name__ == '__main__':
    args = sys.argv[1]
    ip_hostname(args)
