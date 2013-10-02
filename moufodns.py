#!/usr/bin/python

# Copyright (c) 2010 - 2013 Vasileios Porpodas
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#     HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#     WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#     OTHER DEALINGS IN THE SOFTWARE.
#
# This software is licensed under GPL 3 License. http://gplv3.fsf.org/
# For more information on the licence, read the LICENCE file

# moufoDNS is a pseudo DNS server. For details read the README file


###################
# UTILS

import struct

def label2str(label):
    s = struct.pack("!B", len(label))
    s += label
    return s
    
def labels2str(labels):
    s = ''
    for label in labels:
        s += label2str(label)
    s += struct.pack("!B", 0)
    return s

def ipstr2int(ipstr):
    ip = 0
    i = 24
    for octet in ipstr.split("."):
        ip |= (int(octet) << i)
        i -= 8
    return ip

QType2str={1:"A", 2:"NS", 3:"MD(obs)", 4:"MF(obs)", 5:"CNAME", 6:"SOA", 7:"MB(exp)", 8:"MG(exp)", 9:"MR(expr)", 10:"NULL(exp)", 11:"WKS", 12:"PTR", 13:"HINFO", 14:"MINFO", 15:"MX", 16:"TXT"}
def qtype2str (qtype):
    try:
        return QType2str [qtype]
    except:
        return "UNKNOWN"

RCode2str={0:"No Error", 1:"Format Error", 2:"Server Failure", 3:"Name Error", 4:"Not Implemented", 5:"Refused", 6:"YX Domain", 7:"YX RR Set", 8:"NX RR Set", 9:"Not Auth", 10:"Not Zone"}
def rcode2str (rcode):
    try:
        return RCode2str [rcode]
    except:
        return "UNKNOWN"

##############################



import sys
import socket
import struct
import ConfigParser
import signal
import getopt
import time

class DnsError(Exception):
    pass


def parse_variable_field(packet, offset):
    txt = []
    while True:
        txt_len, = struct.unpack('!B', packet[offset:offset+1])
        offset += 1
        two_leftmost_bits = txt_len & 0xc0  # 0xc0 = 1100 0000b
        if two_leftmost_bits != 0x0 and two_leftmost_bits != 0xc0:
            raise DnsError("Invalid txt length %d" % txt_len)
        elif two_leftmost_bits == 0xc0:
            offset = offset - 1 # we have to re-read the first byte
            word, = struct.unpack ("!H", packet [offset : offset + 2])
            offset = offset + 2
            pointer_offset = word & 0x3fff # 0x3fff = 0011 1111 1111 1111b
            dbgPrint ("Compressed name found: offset = %s. ... " % str(pointer_offset), 2)
            name, tmp = parse_variable_field (packet, pointer_offset)
            dbgPrint ("Compressed name: "+name+"\n", 2)
            return name, offset
        if txt_len == 0:
            break
        txt.append(packet[offset : offset + txt_len])
        offset += txt_len
    name = ".".join(txt)
    dbgPrint ("Uncompressed name found: %s\n" % name, 2)
    return name, offset

def parse_header (packet, offset):
    # Header
    dbgPrint ("\n",2)
    dbgPrint ("Header\n",2)
    dbgPrint ("--------\n",2)
    hdr_len = 12
    qid, flags, qdcount, ancount, nscount, arcount, = struct.unpack('!HHHHHH', packet[offset + 0 : offset + hdr_len])
    offset = offset + hdr_len
    dbgPrint ("Qcount:"+str(qdcount)+"\n",2)
    dbgPrint ("ANcount:"+str(ancount)+"\n",2)
    dbgPrint ("NScount:"+str(nscount)+"\n",2)
    dbgPrint ("ARcount:"+str(arcount)+"\n",2)
    
    qr, opcode, aa, tc, rd, ra, zero, rcode = parse_flags (flags)
    return qid, flags, qdcount, ancount, nscount, arcount, qr, opcode, aa, tc, rd, ra, zero, rcode, offset

def parse_flags (flags):
    # flags
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xf
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    zero = (flags >> 4) & 0x7
    rcode = (flags >> 0) & 0xf
    dbgPrint ("QR:"+str(qr)+"\n",2)
    dbgPrint ("Opcode:"+str(opcode)+"\n",2)
    dbgPrint ("AA:"+str(aa)+"\n",2)
    dbgPrint ("TC:"+str(tc)+"\n",2)
    dbgPrint ("RD:"+str(rd)+"\n",2)
    dbgPrint ("RA:"+str(ra)+"\n",2)
    dbgPrint ("Zero:"+str(zero)+"\n",2)
    dbgPrint ("RCode:"+str(rcode)+" ("+str(rcode2str (rcode))+")\n",2)
    return qr, opcode, aa, tc, rd, ra, zero, rcode

def parse_question (packet, offset):
    # Question
    dbgPrint ("Question\n",2)
    dbgPrint ("--------\n",2)
    qname, offset = parse_variable_field (packet, offset)
    dbgPrint ("Qname:"+str(qname)+"\n",2)
    qtype, qclass, = struct.unpack("!HH", packet[offset + 0: offset + 4])
    offset = offset + 4
    dbgPrint ("Qtype:"+str(qtype)+" ("+qtype2str (qtype)+")\n",2)
    dbgPrint ("Qclass:"+str(qclass)+"\n",2)
    if qclass != 1:
        raise DnsError("Invalid class: " + str(qclass))
    dbgPrint ("\n",2)
    return qname, qtype, qclass, offset


def parse_RR1 (packet, offset):
    dbgPrint ("RR1\n",2)
    dbgPrint ("---\n",2)
    aname, offset = parse_variable_field (packet, offset)
    dbgPrint ("Aname:"+str(aname)+"\n",2)
    atype, aclass, attl, ardlen, = struct.unpack ("!HHIH", packet [offset + 0 : offset + 10])
    offset = offset + 10
    dbgPrint ("Atype:"+str(atype)+" ("+qtype2str (atype)+")\n",2)
    dbgPrint ("Aclass:"+str(aclass)+"\n",2)
    dbgPrint ("Attl:"+str(attl)+"\n",2)
    dbgPrint ("ARDlen:"+str(ardlen)+"\n",2)
    return atype, aclass, attl, ardlen, offset

def parse_A (packet, offset):
        ip1, ip2, ip3, ip4, = struct.unpack ("!BBBB", packet [offset + 0 : offset + 4])
        offset = offset + 4
        aipstr=str(ip1)+"."+str(ip2)+"."+str(ip3)+"."+str(ip4)
        dbgPrint ("Aip:"+aipstr+"\n")
        return aipstr, offset

def parse_NS (packet, offset):

        nsname, offset = parse_variable_field (packet, offset)
        dbgPrint ("NSname:"+str(nsname)+"\n",2)
        return nsname, offset
def parse_CNAME (packet, offset):

        cname, offset = parse_variable_field (packet, offset)
        dbgPrint ("Cname:"+str(cname)+"\n",2)
        return cname, offset

def parse_SOA (packet, offset):

        amastername, offset = parse_variable_field (packet, offset)

        aresponsiblename, offset = parse_variable_field (packet, offset)
        aserial, = struct.unpack ("!L", packet [offset + 0 : offset + 4])
        offset = offset + 4

        arefresh, = struct.unpack ("!L", packet [offset + 0 : offset + 4])
        offset = offset + 4

        aretry, = struct.unpack ("!L", packet [offset + 0 : offset + 4])
        offset = offset + 4

        aexpire, = struct.unpack ("!L", packet [offset + 0 : offset + 4])
        offset = offset + 4

        ancttl, = struct.unpack ("!L", packet [offset + 0 : offset + 4])
        offset = offset + 4
        return amastername, aresponsiblename, aserial, arefresh, aretry, aexpire, ancttl, offset

def parse_PTR (packet, offset):

        ptrname, offset = parse_variable_field (packet, offset)
        dbgPrint ("PTRname:"+str(ptrname)+"\n",2)
        return ptrname, offset

def parse_MX (packet, offset):

        apref, = struct.unpack ("!H", packet [offset + 0 : offset + 2])
        offset = offset + 2
        aexchange, offset = parse_variable_field (packet, offset)
        dbgPrint ("Aexchange:"+str(aexchange)+"\n",2)
        return aexchange, offset

def parse_TXT (packet, offset):

        atxt, offset = parse_variable_field (packet, offset)
        dbgPrint ("Atxt:"+str(atxt)+"\n",2)
        return atxt, offset

def parse_response(packet):
    offset = 0
    # Header, flags
    qid, flags, qdcount, ancount, nscount, arcount, qr, opcode, aa, tc, rd, ra, zero, rcode, offset = parse_header (packet, offset)
    if rcode2str (rcode) == "No Error":
        pass
    else:
        return rcode2str (rcode)
    if qr != 1 or opcode != 0 or qdcount == 0:
        raise DnsError("Invalid query")
    dbgPrint ("\n",2)
    # Question
    qname, qtype, qclass, offset = parse_question (packet, offset)

    # RR
    if qtype2str (qtype) == "A":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        aipstr, offset = parse_A (packet, offset)
        return aipstr
    elif qtype2str (qtype) == "NS":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        nsname, offset = parse_NS (packet, offset)
        return nsname
    elif qtype2str (qtype) == "CNAME":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        cname, offset = parse_CNAME (packet, offset)
        return cname
    elif qtype2str (qtype) == "SOA":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        amastername, aresponsiblename, aserial, arefresh, aretry, aexpire, ancttl, offset = parse_SOA (packet, offset)
        return "SOA"
    elif qtype2str (qtype) == "PTR":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        ptrname, offset = parse_PTR (packet, offset)
        return ptrname
    elif qtype2str (qtype) == "MX":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        aexchange, offset = parse_MX (packet, offset)
        return aexchange
    elif qtype2str (qtype) == "TXT":
        atype, aclass, attl, ardlen, offset = parse_RR1 (packet, offset)
        atxt, offset = parse_TXT (packet, offset)
        return atxt
    else:
        return "UNKNOWN"
    # Answer
    
        
        






def domain_matches (full, part):
    # always match when given "*"
    if part == "*":
        return True
    else:
        # reverse full and part since find() compares from left to right.
        if full[::-1].find(part[::-1]) == 0:
            return True
        else:
            return False
        

def query_in_proxy_domains (queryStr):
    if conf.PROXY_RE != None:
        dbgPrint ("conf.PROXY_RE:\n",2)
        for proxy_domain_re in conf.PROXY_RE.keys():
            if re_matches (proxy_domain_re, queryStr):
                ip_port = conf.PROXY_RE[proxy_domain_re]
                ip_port_split = parse_psv (ip_port) 
                ip = ip_port_split [0]
                try:
                    port = ip_port_split [1]
                except:
                    port = 53
                dbgPrint ("proxy ip: %s\n" % ip, 2)
                dbgPrint ("proxy port: %s\n" % ip, 2)
                return True, ip, port
    return False, 0, 0


# create socket. return None on failure
def udp_safe_socket ():
    # 3 seconds socket timeout 
    SOCKTIMEOUT = 3
    try:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.settimeout(SOCKTIMEOUT)
        return udps
    except:
        dbgPrint ("ERROR: can't create udp socket\n")
        return None

# send PKT to ADDR:PORT through SKT. return None on failure
def socket_safe_send (skt, pkt, addr, port):
    try:
        skt.sendto(pkt, (addr, port))
        return True
    except:
        dbgPrint ("ERROR: sending data to "+str(addr)+":"+str(port)+"through socket.\n")
        return None

# receive packet of BUFSIZE through SKT. return (None, None) on failure.
def socket_safe_rcv (skt, bufsize):
    try:
        rcvd_pkt, src_addr = skt.recvfrom(bufsize)   # max UDP DNS pkt size
        return (rcvd_pkt, src_addr)
    except:
        dbgPrint ("ERROR: receiving data through socket.\n")
        return (None, None)

# close SKT. return None on failure
def socket_safe_close (skt):
    try:
        skt.close()
        return True
    except:
        dbgPrint ("ERROR: closing socket.\n")
        return None


# send REQ_PKT to PROXY_ADDR:PROXY_PORT. If something fails return None.
# else return the received packet.
def proxy_rqst (req_pkt, proxy_addr, proxy_port):
    proxy_port = 53

    dbgPrint ("PROXY:"+str(proxy_addr)+":"+str(proxy_port)+"\n",2)
    udps = udp_safe_socket ()
    if udps == None:
        return None

    dbgPrint ("proxy socket created. Trying to send data...\n", 2)
    send_result = socket_safe_send (udps, req_pkt, proxy_addr, proxy_port)
    if send_result == None:
        return None

    dbgPrint ("proxy data sent. Trying to receive data...\n", 2)
    rcvd_pkt, src_addr = socket_safe_rcv (udps, 512)
    if rcvd_pkt == None:
        return None

    dbgPrint ("proxy data received. Closing socket...\n", 2)
    close_result = socket_safe_close (udps)
    if close_result == None:
        return None

    return rcvd_pkt

def safe_open (filename, mode):
    try:
        fp=open(filename, mode)
    except:
        die("Error: Opening log file "+filename+" for +\""+str(mode)+"\"\n" )  
    return fp

def safe_write (fp, stuff):
    try:
        fp.write(stuff)
    except:
        die("Error: Could not write to file.\n")

def safe_close (fp):
    try:
        fp.close()
    except:
        die("Error: Closing file "+filename+".\n")
    return fp


def re_matches (reg_ex, str_in):
    import re
    try:
        m = re.match (reg_ex, str_in)
        result = m.group (0)
    except:
        dbgPrint ("re_match: NO match "+reg_ex+", "+str_in+"\n", 2)
        return False

    try:
        if result == str_in:
            dbgPrint ("re_match: MATCH "+reg_ex+", "+str_in+"\n", 2)
            return True
        else:
            dbgPrint ("re_match: NO match "+reg_ex+", "+str_in+"\n", 2)
            return False
    except:
        die ("ERROR: in regular expression: "+str(reg_ex)+" when trying to match string "+str(str_in)+" \n")


def query_response(queryStr):
    # IF in conf.OVERRIDES then get ip from conf.OVERRIDES list
    if conf.OVERRIDES != None:
        if queryStr in conf.OVERRIDES.keys():
            return conf.OVERRIDES[queryStr]
    if conf.OVERRIDES_RE != None:
        dbgPrint ("conf.OVERRIDES:\n", 2)
        for reg_ex in conf.OVERRIDES_RE.keys():
            if re_matches (reg_ex, queryStr):
                ip=str(conf.OVERRIDES_RE[reg_ex])
                return ip
    die ("ERROR: missing default regular expression from conf.OVERRIDES\n")
    



def serve():

    while True:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            dbgPrint("Trying to listen on "+str(conf.LISTEN_HOST)+":"+str(conf.LISTEN_PORT)+" ... ")
            udps.bind((conf.LISTEN_HOST, conf.LISTEN_PORT))
        except:
            die("ERROR: Unable to  listen on "+str(conf.LISTEN_HOST)+":"+str(conf.LISTEN_PORT)+" . Check -h and/or -p parameters. You require root privileges to listen on port 53.\n")
        dbgPrint ("OK\n")
        ns_resource_records = ar_resource_records = []

        # start counter from last entry
        if conf.LOGFILE != None:
            fp = None
            try:
                fp=open(conf.LOGFILE,"r")
            except:
                sys.stderr.write("Warning: Opening logfile: "+conf.LOGFILE+" for reading\n" )
                sys.stderr.write("         This is OK if it is the first time you run it, or no log exists.\n" )
            count=0         # Always start with 0

        else:
            count=0



        dbgPrint ("Listening for DNS requests ...\n")
        while True:
            count+=1
            try:
                req_pkt, src_addr = udps.recvfrom(512)   # max UDP DNS pkt size
            except socket.error:
                sys.stderr.write("Error: socket error, udps.recvfrom(512)\n" )            
                break

            qid = None
            exception_rcode = None
            try:
                qid, question, qtype, qclass = parse_request(req_pkt)
            except:
                exception_rcode = 1
                #raise Exception("could not parse query")
                sys.stderr.write("%d Error: could not parse query. Source: %s\n" % (count, str(src_addr[0])))
                continue
                

                

            # Create response packet
            prefix = ""
            question = map(lambda x: x.lower(), question)
            query = question

            query_str = ".".join(query)

            use_proxy, proxy_ip, proxy_port = query_in_proxy_domains (query_str)
            if use_proxy:
                # if proxy, act as a dns proxy.
                resp_pkt = proxy_rqst (req_pkt, proxy_ip, proxy_port)
                if resp_pkt == None:
                    dbgPrint ("ERROR: proxy: something went wrong.\n:")
                    continue
                try:
                    resp_str = parse_response (resp_pkt)
                except:
                    dbgPrint ("ERROR: parse_response () failed.\n")
                    continue
                prefix = "(prx "+str(proxy_ip)+":"+str(proxy_port)+")"
            else:
                resp_str = query_response(query_str)
                an_resource_records = [{'qtype': 1, 'qclass':qclass, 'ttl': 500, 'rdata': struct.pack("!I",ipstr2int(resp_str))}]
                rcode = 0
                resp_pkt = format_response(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records)



            # Print on the console
            isFiltered = filter (query)
            if isFiltered:
                prefix += "(FILT)"
            lt=time.localtime(time.time())
            thedate=str(lt.tm_year)+"/"+str(lt.tm_mon)+"/"+str(lt.tm_mday)+conf.DELIMITER+str(lt.tm_hour)+":"+str(lt.tm_min)+":"+str(lt.tm_sec)
            # FIXME: "," is used by moufostats as a delimiter, so it should not be in the query string of the log file. 
            # Replace it by "." This is a HACK, we should support escape sequences in both moufodns and moufostats.
            query_str = query_str.replace (conf.DELIMITER, ".") 
            output=str(count)+conf.DELIMITER+query_str+conf.DELIMITER+resp_str+conf.DELIMITER+str(src_addr[0])+":"+str(src_addr[1])+conf.DELIMITER+thedate+"\n"
            dbgPrint(prefix + conf.DELIMITER + output, 1)



            # Print on the logfile
            if (not isFiltered):
                if conf.LOGFILE!=None:
                    fp = safe_open (conf.LOGFILE, "a")
                    safe_write (fp, output)
                    safe_close (fp)





            # SEND response 
            try:
                udps.sendto(resp_pkt, src_addr)
            except:
                sys.stderr.write("Error: socket error, udps.sendto(resp_pkt, src_addr)\n" )  
                break
        time.sleep(1)

    
def filter(query):
    queryStr=str(".".join(query))

    if conf.FILTER_LEVEL == "whitelist-names":
        # if no names, filter everything
        if conf.WHITELIST_NAMES == None:
            return True

        if queryStr in conf.WHITELIST_NAMES:
            return False
        else:
            return True

    if conf.FILTER_LEVEL=="whitelist-domains":
        if len(query)>=1: #If not empty request, check domain name
            # if no domains, filter all of them
            if conf.WHITELIST_DOMAINS == None:
                return True
            if not query[-1] in conf.WHITELIST_DOMAINS:
                return True
            else:
                return False
        else: #Don't filter empty requests
            return False
    elif conf.FILTER_LEVEL=="blacklist-names":
        domain=".".join(query)
        # if no blacklist names, don't filter anything
        if conf.BLACKLIST_NAMES == None:
            return False

        if domain in conf.BLACKLIST_NAMES:
            return True
        else:
            return False
    elif conf.FILTER_LEVEL=="none":
        return False

def compute_name_server_resources(name_servers):
    ns = []
    ar = []
    for name_server, ip, ttl in name_servers:
        ns.append({'qtype':2, 'qclass':1, 'ttl':ttl, 'rdata':labels2str(name_server)})
        ar.append({'qtype':1, 'qclass':1, 'ttl':ttl, 'rdata':struct.pack("!I", ip)})
    return ns, ar
        
def parse_request(packet):
    hdr_len = 12
    header = packet[:hdr_len]
    qid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', header)
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xf
    rd = (flags >> 8) & 0x1
    #print "qid", qid, "qdcount", qdcount, "qr", qr, "opcode", opcode, "rd", rd
    if qr != 0 or opcode != 0 or qdcount == 0:
        raise DnsError("Invalid query")
    body = packet[hdr_len:]
    labels = []
    offset = 0
    while True:
        label_len, = struct.unpack('!B', body[offset:offset+1])
        offset += 1
        if label_len & 0xc0:
            raise DnsError("Invalid label length %d" % label_len)
        if label_len == 0:
            break
        label = body[offset:offset+label_len]
        offset += label_len
        labels.append(label)
    qtype, qclass, = struct.unpack("!HH", body[offset:offset+4])
    if qclass != 1:
        raise DnsError("Invalid class: " + qclass)
    return (qid, labels, qtype, qclass)



def format_response(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records):
    resources = []
    resources.extend(an_resource_records)
    num_an_resources = len(an_resource_records)
    num_ns_resources = num_ar_resources = 0
    if rcode == 0:
        resources.extend(ns_resource_records)
        resources.extend(ar_resource_records)
        num_ns_resources = len(ns_resource_records)
        num_ar_resources = len(ar_resource_records)
    pkt = format_header(qid, rcode, num_an_resources, num_ns_resources, num_ar_resources)
    pkt += format_question(question, qtype, qclass)
    for resource in resources:
        pkt += format_resource(resource, question)
    return pkt

def format_header(qid, rcode, ancount, nscount, arcount):
    flags = 0
    flags |= (1 << 15)
    flags |= (1 << 10)
    flags |= (rcode & 0xf)
    hdr = struct.pack("!HHHHHH", qid, flags, 1, ancount, nscount, arcount)
    return hdr

def format_question(question, qtype, qclass):
    q = labels2str(question)
    q += struct.pack("!HH", qtype, qclass)
    return q

def format_resource(resource, question):
    r = ''
    r += labels2str(question)
    r += struct.pack("!HHIH", resource['qtype'], resource['qclass'], resource['ttl'], len(resource['rdata']))
    r += resource['rdata']
    return r

def dbgPrint (msg, level=0):
    if conf.VERBOSE_LEVEL > level:
        sys.stdout.write(str(msg))
    
def die(msg):
    sys.stderr.write(msg)
    sys.exit(-1)

# parse conf.DELIMITER separated values in STRING. regurn OUT_LIST
def parse_dsv (string, delimiter):
    in_list = string.split(delimiter)
    out_list = []
    for item in in_list:
        out_list.append (item.strip())
    return out_list
# parse semicolon ":" separated values in STRING
def parse_ssv (string):
    return parse_dsv (string, ":")

# parse comma "," separated values in STRING
def parse_csv (string):
    return parse_dsv (string, ",")

# parse pipe "|" separated values in STRING
def parse_psv (string):
    return parse_dsv (string, "|")


def usage(cmd):
    die("Usage: %s [-h <HOST>] [-p <PORT>] [-w <LOG FILE>] [-f <FILTER OPTIONS>] [-c <CONFIG FILE>] [-d <conf.DELIMITER>] [-n <IP WHEN NOT FOUND>] [--proxy \'<DOMAIN1 REGULAR EXPRESSION>:<DNS1 IP>|[<DNS1 PORT>], ...\'] [--blacklist-names <NAME1,NAME2,...>] [--whitelist-names <NAME1,NAME2,...>] [--whitelist-domains <DOMAIN1,DOMAIN2,...>] [--overrides <NAME1:IP1,NAME2:IP2...>] [--no-config] [-v <VERBOSE LEVEL>] [--help]\n\
\n\
-h <HOST>                    The hostname or IP address where the server will\n\
                                listen for incoming connections. Default: all\n\
-p <PORT>                    The port that the server will listen at.\n\
                                Default port = 53 (requires root privileges).\n\
-w <LOG FILE>                Instead of printing on stdout, print on <LOG FILE>\n\
-f <FILTER OPTIONS>          This controls what gets filtered out of the logfile\n\
                               Filter types can be: blacklist-names\n\
                                                  , whitelist-names\n\
                                                  , whitelist-domains\n\
-c <CONFIG FILE>             Configuration file path. Default: moufodns.config\n\
-d <conf.DELIMITER>               <conf.DELIMITER> separates the values on the output\n\
                               Default delimiter=\",\"\n\
-n <IP WHEN NOT FOUND>       This IP will be returned when the system dns \n\
                               is queried but returned not found. (ASK SYSTEM)\n\
--proxy \'<DOMAIN1 REGULAR EXPRESSION>:<DNS1 IP>:[<DNS1 PORT>],...\'\n\
                             <DOMAIN1 REGULAR EXPRESSION> is a regular expr\n\
                              that if matched will use as dns server <DNS1 IP>\n\
                              with port <DNS1 PORT> for this dns request\n\
                              Proxy entries are separated by \",\" (no space)\n\
                              If <DNS1 PORT> is missing, it defaults to 53.\n\
The following require the corresponding -f <FILTER OPTIONS> option. They\n\
  control what is filtered out of the log file.\n\
--blacklist-names <NAME1,NAME2,...> Comma separated list of blacklisted names\n\
                                      Used in filtering of type blacklist-names\n\
--whitelist-names <NAME1,NAME2,...> Comma separated list of whitelisted names\n\
                                      Used in filtering of type whitelist-names\n\
--whitelist-domains <DOMAIN1,DOMAIN2,...> Comma separated list of domains\n\
                                      Used in filtereing type whitelist-domains\n\
--overrides <NAME1:IP1,NAME2:IP2...> Override the default return ip address for\n\
                                       all these name:ip pairs.\n\
--no-config                   Don't use the config file, get all options from\n\
                                the command line arguments\n\
-v <VERBOSE LEVEL>            The verbosity level 0-2. Default is 2.\n\
                                Values > 3 are only for debug purposes.\n\
--help                        Print this help message\n\
" % cmd)

import collections
# Accessing the config file in a safe way.
class Safe_config:
    config = None
    def __init__ (self):
        import ConfigParser
        self.config = ConfigParser.ConfigParser({}, collections.OrderedDict)
        self.config.read (conf.CONFIG_FILE)
        
    def get (self, str1, str2):
        try:
            result = self.config.get (str1, str2)
        except:
            die ("ERROR: reading config file !\nDETAILS: Section \"["+str1+"]\" -> entry \""+str2+":<STRING>\" is missing !\n");
        return result        

    # returns None if string empty
    def get (self, str1, str2):
        try:
            result = self.config.get (str1, str2)
        except:
            die ("ERROR: reading config file !\nDETAILS: Section \"["+str1+"]\" -> entry \""+str2+":<STRING>\" is missing !\n");
        if result == "":
            return None
        return result        

    # does NOT exit if not found in config
    def get_weak (self, str1, str2):
        try:
            result = self.config.get (str1, str2)
            return result
        except:
            dbgPrint ("WARNING: reading config file !\nDETAILS: Section \"["+str1+"]\" -> entry \""+str2+":<STRING>\" is missing !\n");
        return None

    # does NOT exit if not found in config. Return None if string empty
    def get_weak_none (self, str1, str2):
        try:
            result = self.config.get (str1, str2)
            if result == "":
                return None
            return result
        except:
            dbgPrint ("WARNING: reading config file !\nDETAILS: Section \"["+str1+"]\" -> entry \""+str2+":<STRING>\" is missing !\n");
        return None

    def getint (self, str1, str2):
        try:
            result = self.config.getint (str1, str2)
        except:
            die ("ERROR: reading config file !\nDETAILS: Section \"["+str1+"]\" -> entry \""+str2+":<INTEGER>\" is missing !\n");
        return result        

    def items (self, str1):
        try:
            result = self.config.items (str1)
        except:
            die ("ERROR: reading config file !\nDETAILS: Section \"["+str1+"]\" is missing !\n");
        return result        



def read_config ():
        # global configuration variables
        global conf

        # CONFIGURATION BEGIN
        try:
            fp=open(conf.CONFIG_FILE,"r")
        except:
            die("Error: Opening config file: "+conf.CONFIG_FILE+" for writting\n" )  
        try:
            fp.close()
        except:
            die("Error: Closing file "+conf.CONFIG_FILE+".\n")


        safe_config = Safe_config ()
        if conf.LISTEN_PORT == None:
            conf.LISTEN_PORT = safe_config.getint ("config", "listen port")
        if conf.LISTEN_HOST == None:
            conf.LISTEN_HOST = safe_config.get ("config", "listen host")
        if conf.LOGFILE == None:
            conf.LOGFILE = safe_config.get_weak_none ("config", "logfile")
        if conf.IP_WHEN_NOT_FOUND == None:
            conf.IP_WHEN_NOT_FOUND = safe_config.get ("config", "ip when not found") #"0.0.0.0" #if domain not found on system's dns return this ip
        if conf.FILTER_LEVEL == None:
            conf.FILTER_LEVEL = safe_config.get ("config", "filter level")
        if conf.DELIMITER == None:
            conf.DELIMITER = safe_config.get ("config", "log delimiter")

        if conf.OVERRIDES == None:
            conf.OVERRIDES=collections.OrderedDict ({})
            all_overrides=safe_config.items ("overrides")
            for pair in all_overrides:
                conf.OVERRIDES[pair[0]]=pair[1]

        if conf.OVERRIDES_RE == None:
            conf.OVERRIDES_RE=collections.OrderedDict ({})
            all_overrides=safe_config.items ("overrides RE")
            for pair in all_overrides:
                conf.OVERRIDES_RE[pair[0]]=pair[1]

        if conf.PROXY_RE == None:
            conf.PROXY_RE=collections.OrderedDict ({})
            all_proxies=safe_config.items ("proxy RE")
            for pair in all_proxies:
                conf.PROXY_RE[pair[0]]=pair[1]


        #blacklist works only with -f blacklist
        if conf.BLACKLIST_NAMES_str == None:
            conf.BLACKLIST_NAMES_str = safe_config.get_weak ("log filters", "blacklist names")

        # whitelist. These domains get logged no matter what
        if conf.WHITELIST_NAMES_str == None:
            conf.WHITELIST_NAMES_str = safe_config.get_weak ("log filters", "whitelist names")


        if conf.WHITELIST_DOMAINS_str == None:
            conf.WHITELIST_DOMAINS_str = safe_config.get_weak ("log filters", "whitelist domains")


        # CONFIGURATION END

def parse_complex_str ():
    # global configuration variables
    global conf

    if conf.BLACKLIST_NAMES_str != None:
        conf.BLACKLIST_NAMES = parse_csv (conf.BLACKLIST_NAMES_str)    
    if conf.WHITELIST_NAMES_str != None:
        conf.WHITELIST_NAMES = parse_csv (conf.WHITELIST_NAMES_str)
    if conf.WHITELIST_DOMAINS_str != None:
        conf.WHITELIST_DOMAINS = parse_csv (conf.WHITELIST_DOMAINS_str)

            
# read command line arguments
def read_arguments ():
    global conf 

    try:
        options, filenames = getopt.getopt(sys.argv[1:], "p:h:m:w:f:c:d:n:v:", ["help", "blacklist-names=", "whitelist-names=", "whitelist-domains=", "overrides=", "no-config", "proxy=", "proxy-domains="])
    except getopt.GetoptError:
        usage(sys.argv[0])

    for option, value in options:
        if option == "-p":
            conf.LISTEN_PORT = int(value)
        elif option == "-h":
            conf.LISTEN_HOST = value
        elif option == "-w":
            conf.LOGFILE= str(value)
        elif option == "-f":
            conf.FILTER_LEVEL=str(value)
        elif option == "-c":
            conf.CONFIG_FILE = str(value)
        elif option == "-d":
            conf.DELIMITER = str(value)
        elif option == "-n":
            conf.IP_WHEN_NOT_FOUND = str(value)
        elif option == "--blacklist-names":
            conf.BLACKLIST_NAMES_str = str(value)
        elif option == "--whitelist-names":
            conf.WHITELIST_NAMES_str = str(value)
        elif option == "--whitelist-domains":
            conf.WHITELIST_DOMAINS_str = str(value)
        elif option == "--help" or option == "-help":
            usage(sys.argv[0])
        elif option == "--overrides" or option == "-overrides":
            conf.OVERRIDES = {}
            csv_pairs = str(value)
            for pair in parse_csv (csv_pairs):
                pair_parts = parse_ssv (pair)
                try:
                    conf.OVERRIDES [pair_parts[0]] = pair_parts[1]
                except:
                    die ("ERROR when parsing overrides: "+str(pair_parts)+".\n Can't find all parts arround the \":\". Maybe space between values?\n")

            conf.OVERRIDES_RE = {}
            csv_pairs = str(value)
            for pair in parse_csv (csv_pairs):
                pair_parts = parse_ssv (pair)
                try:
                    conf.OVERRIDES_RE [pair_parts[0]] = pair_parts[1]
                except:
                    die ("ERROR when parsing overrides RE: "+str(pair_parts)+".\n Can't find all parts arround the \":\". Maybe space between values?\n")

        elif option == "--proxy" or option == "-proxy":
            conf.PROXY_RE = {}
            csv_pairs = str(value)
            for pair in parse_csv (csv_pairs):
                pair_parts = parse_ssv (pair)
                try:
                    conf.PROXY_RE [pair_parts[0]] = pair_parts[1]
                except:
                    die ("ERROR when parsing proxy RE: "+str(pair_parts)+".\n Can't find all parts arround the \":\". Maybe space between values?\n")


        elif option == "--no-config" or option == "-no-config":
            conf.NO_CONFIG = True
        elif option == "-v":
            conf.VERBOSE_LEVEL = int(value)


# Check whether the minimum requirements are met. If not, set hard-coded defaults.
def set_minimum_requirements ():
    global conf 
    if conf.VERBOSE_LEVEL == None:
        try:
            conf.VERBOSE_LEVEL = config.getint ("config", "verbose level")
        except:
            conf.VERBOSE_LEVEL = 2
    if conf.LISTEN_PORT == None:
        conf.LISTEN_PORT = 53
    if conf.LISTEN_HOST == None:
        conf.LISTEN_HOST = "0.0.0.0"
    if conf.DELIMITER == None:
        conf.DELIMITER = ","

# print start-up dump
def print_startup ():
    global conf 
    version="0.64"
    dbgPrint("+-------------------------------------+\n" )
    dbgPrint("|  MOUFO DNS online (powered by pwmn) |\n" )
    dbgPrint("+-------------------------------------+\n" )
    dbgPrint("                                   v"+version+"\n" )
    if (conf.NO_CONFIG):
        dbgPrint("Config file          : --no-config\n")
    else:
        dbgPrint("Config file          : %s\n" % (conf.CONFIG_FILE))
    dbgPrint("Listening on host    : %s\n" % (conf.LISTEN_HOST))
    dbgPrint("Listening on port    : %d\n" % (conf.LISTEN_PORT))
    dbgPrint("LogFile              : %s\n" % (conf.LOGFILE))
    dbgPrint("Ip when not found    : %s\n" % (conf.IP_WHEN_NOT_FOUND))
    dbgPrint("Filter Level         : %s\n" % (conf.FILTER_LEVEL))
    dbgPrint("Delimiter            : %s\n" % (conf.DELIMITER))
    if conf.FILTER_LEVEL=="blacklist-names":
        dbgPrint("Blacklist names      :\n")
        if conf.BLACKLIST_NAMES != None:
            for bl in conf.BLACKLIST_NAMES:
                dbgPrint("                       %s\n" % (bl))
    if conf.FILTER_LEVEL=="whitelist-names":
        dbgPrint("Whitelist names      :\n")
        if conf.WHITELIST_NAMES != None:
            for wl in conf.WHITELIST_NAMES:
                dbgPrint("                       %s\n" % (wl))
    if conf.FILTER_LEVEL=="whitelist-domains":
        dbgPrint("Whitelist domains    :\n")
        if conf.WHITELIST_DOMAINS != None:
            for wl in conf.WHITELIST_DOMAINS:
                dbgPrint("                       %s\n" % (wl))
    dbgPrint("Overrides            :\n")
    if conf.OVERRIDES != None:
        for name in conf.OVERRIDES.keys():
            dbgPrint ("                       "+str(name)+":"+str(conf.OVERRIDES[name])+"\n")
    dbgPrint("Overrides RE         :\n")
    if conf.OVERRIDES_RE != None:
        for name in conf.OVERRIDES_RE.keys():
            dbgPrint ("                       "+str(name)+":"+str(conf.OVERRIDES_RE[name])+"\n")
    dbgPrint("Proxy RE             :\n")
    if conf.PROXY_RE != None:
        for name in conf.PROXY_RE.keys():
            dbgPrint ("                       "+str(name)+":"+str(conf.PROXY_RE[name])+"\n")

    dbgPrint("Verbose Level        : %d\n" % (conf.VERBOSE_LEVEL))
    sys.stdout.flush()
    sys.stderr.flush()




# global default configuration variables
class CONF:
    LISTEN_PORT = None
    LISTEN_HOST = None
    MOUFO_IP = None
    LOGFILE = None
    FILTER_LEVEL = None
    CONFIG_FILE = "moufodns.conf"
    IP_WHEN_NOT_FOUND = None
    DELIMITER = None
    NO_CONFIG = False
    VERBOSE_LEVEL = None
    OVERRIDES = None
    OVERRIDES_RE = None
    PROXY_RE = None
    BLACKLIST_NAMES = None
    WHITELIST_NAMES = None
    WHITELIST_DOMAINS = None

    BLACKLIST_NAMES_str = None
    WHITELIST_NAMES_str = None
    WHITELIST_DOMAINS_str = None


conf = CONF ()

def check_version ():
    if sys.version_info < (2, 7):
        die ("ERROR: Old python version detected. Version > 2.7 is required for OrderedDict.\n")

if __name__=="__main__":
    
    # make sure python is >2.7 so that ordered dictionaries are supported.
    check_version ()

    # read command line arguments and set the CONFIGURATION VARIABLES (above).
    read_arguments ()

    # read the config file and set the CONFIGURATION VARIABLES (above).
    if not conf.NO_CONFIG:
        read_config ()

    # parse the input from the arguments/config that is not a single entity
    # comma separated values (CSVs) etc.
    parse_complex_str ()

    # Check whether the minimum requirements are met. If not, set 
    # hard-coded defaults.
    set_minimum_requirements ()

    # print start-up dump
    print_startup ()

    # start the server
    try:
        serve()
    except KeyboardInterrupt:
        die ("Die hippie die!\n")

 
