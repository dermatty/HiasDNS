#! /usr/bin/python
import threading
import time, sys
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from threading import Thread
import ssl
import socket
import socketserver
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

FWDSERVERS = {}
DNSQUERYTHREADS = []




class DNSQueryThread(Thread):
    def __init__(self, server_ip, proto, tier, lock):
        Thread.__init__(self)
        self.server_ip = server_ip
        self.proto = proto
        self.tier = tier
        self.lock = lock
        self.result = None
        self.q = None
        self.daemon = True
        self.dt = 0.0
    
    def get_result(self, timeout=2.0):
        t0 = time.time()
        while not self.result and time.time() - t0 < timeout:
            time.sleep(0.001)
        if time.time() - t0 >= timeout:
            self.result = []
        r = self.result
        self.result = None
        return r
    
    def get_dt(self):
        with self.lock:
            return self.dt
    
    def run(self):
        while True:
            if not self.q:
                time.sleep(0.001)
                continue
            try:
                r = []
                t0 = time.time()
                if self.proto == "UDP":
                    r = dns.query.udp(self.q, self.server_ip, timeout=2).answer
                elif self.proto == "TLS":
                    r = dns.query.tls(self.q, self.server_ip, timeout=2).answer
                with self.lock:
                    self.result = r
                    self.q = None
                    if self.dt == 0.0:
                        self.dt = (time.time() - t0)
                    else:
                        self.dt = (self.dt * 0.2 + (time.time() - t0) * 0.8) / 2
            except (Exception, ):
                continue

def handle_query(data, addr, sock):
    #UPSTREAM_DNS_SERVER = ('1.1.1.1', 53)
    ## with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
    #    request = DNSRecord.parse(data)
    #    print(
    #        "Forwarding query for " + str(request.q.qname) + " to upstream server" + str(UPSTREAM_DNS_SERVER) + " ...")
    #   upstream_sock.sendto(data, UPSTREAM_DNS_SERVER)
    #   response, _ = upstream_sock.recvfrom(512)
    #    sock.sendto(response, addr)
    # dns over tls geht so:
    ## https://github.com/melvilgit/dns-over-tls/blob/master/dnsovertls.py

    UPSTREAM_DNS_SERVER = ('1.1.1.1', 53)
    print(DNSRecord.parse(data))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
        print("Forwarding query to upstream server...")
        upstream_sock.sendto(data, UPSTREAM_DNS_SERVER)
        response, _ = upstream_sock.recvfrom(512)
        print(DNSRecord.parse(response))
        sock.sendto(response, addr)
        print("Response forwarded to client.")

    """with conn as sock0:
        sock0.send(data)
        print("#1")
        response = sock0.recv(4096)
    print("#2")
    sock.sendto(response, addr)"""

class DNSHandler(socketserver.BaseRequestHandler):
        
    def handle(self):
        global FWDSERVERS
        global DNSQUERYTHREADS
        print("-" * 70)
        data = self.request[0].strip()
        socket0 = self.request[1]
        #data, addr = sock.recvfrom(512)
        #dns_handler(data, addr, sock)
        UPSTREAM_DNS_SERVER = ('8.8.8.8', 53)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            request = DNSRecord.parse(data)
            print("Forwarding query for " + str(request.q.qname) + " to upstream server" + str(UPSTREAM_DNS_SERVER) + " ...")
            upstream_sock.sendto(data, UPSTREAM_DNS_SERVER)
            response =  upstream_sock.recv(1512)
            socket0.sendto(response, self.client_address)
            print("Response forwarded to client.")

        """try:
            request = DNSRecord.parse(data)
            t_id =  threading.current_thread().ident
            print(str(t_id) + " received request for: " + str(request.q.qname))
            
            # Create a DNS response with the same ID and the appropriate flags
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
            
            qname = str(request.q.qname).strip()
            qname0 = dns.name.from_text(qname)
            q = dns.message.make_query(qname0, dns.rdatatype.A)
            
            if str(qname).strip() == ".":
                raise Exception
            elif not validators.domain(qname[:-1]):
                raise Exception
            
            for server_ip in self.fwdservers:
                print("Querying server " + str(server_ip) + " for " + str(qname0))
                proto = self.fwdservers[server_ip]
                t0 = time.time()
                if proto == "UDP":
                    r = dns.query.udp(q, server_ip, timeout=2).answer
                elif proto == "TLS":
                    r = dns.query.tls(q, server_ip, timeout=2).answer
                else:
                    r = []
                dtms = int((time.time() - t0) * 1000)
                if r:
                    print("Received answer from " + str(server_ip) + " in " + str(dtms) + " ms!")
                else:
                    print("Received NO answer from " + str(server_ip) + " in " + str(dtms) + " ms!")
            
            r = []
            primary = sorted([(t, t.dt, t.server_ip) for t in DNSQUERYTHREADS if t.tier == "primary"],
                             key=lambda x:x[1])
            print("primary", primary)
            for t, _, _ in primary:
                #print("Querying server " + str(t.server_ip) + " for " + str(qname0))
                with t.lock:
                    t.q = q
                r = t.get_result(timeout=1)
                if r:
                    break
                #dtms = int(t.dt * 1000)
                #if r:
                #    print("Received answer from " + str(t.server_ip) + " in avg. " + str(dtms) + " ms!")
                #else:
                #    print("Received NO answer from " + str(t.server_ip) + " in avg. " + str(dtms) + " ms!")

            if not r:
                r = []
                backup = sorted([(t, t.dt) for t in DNSQUERYTHREADS if t.tier == "backup"], key=lambda x: x[1])
                print("backup", backup)
                for t, _ in backup:
                    # print("Querying server " + str(t.server_ip) + " for " + str(qname0))
                    with t.lock:
                        t.q = q
                    r = t.get_result()
                    if r:
                        break
            print(r)
            
            if r:
                print("Received answer from " + str(t.server_ip) + " for " + str(qname0) + " in avg. " + str(t.dt) + " ms!")
                try:
                    r0 = str(r[-1]).split("\n")
                    r00 = [r01.split("IN A")[-1].strip() for r01 in r0]
                    #print(r00)
                    for r000 in r00:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(r000)))
                except:
                    pass
            else:
                print("DNS entry not found!")
            socket.sendto(reply.pack(), self.client_address)
        except Exception as e:
            socket.sendto(reply.pack(), self.client_address)
            print(f"Error handling request: {e}")"""
        
class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

def start():
    # on client side:
    #  dig @127.0.0.1 -p 5853 orf.at
    #       or
    # nslookup -port=5853 orf.at localhost

    # tls sockets: https://gist.github.com/marshalhayes/ca9508f97d673b6fb73ba64a67b76ce8

    global FWDSERVERS
    global DNSQUERYTHREADS
    FWDSERVERS = {"10.4.0.1": {"proto": "UDP", "tier": "primary", "hostname": ""},
                  "10.5.0.1": {"proto": "UDP", "tier": "primary"},
                  "10.128.0.1": {"proto": "UDP", "tier": "primary"},
                  "8.8.8.8": {"proto": "UDP", "tier": "backup"},
                  "9.9.9.9": {"proto": "UDP", "tier": "backup"},
                  "1.1.1.1": {"proto": "UDP", "tier": "backup"}}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    this_dns_server = ("0.0.0.0", 5853)
    sock.bind(this_dns_server)
    print("DNS server started on " + str(this_dns_server))
    #CONTEXT = ssl.create_default_context()
    #CONTEXT = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    #CONTEXT.load_verify_locations("/home/stephan/CA_ssl/rootCA.pem")
    #conn = CONTEXT.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname="dns.quad9.net")
    #conn.connect(("9.9.9.9", 853))
    #print("connected")
    while True:
        data, addr = sock.recvfrom(1024)
        t = threading.Thread(target=handle_query, args=(data, addr, sock, ))
        t.daemon = True
        t.start()

    #t = threading.Thread(target=server.serve_forever)
    #t.daemon = True  # don't hang on exit
    #t.start()
    #while True:
    #    time.sleep(1)
    
    #server.serve_forever()
    
    # from https://www.geeksforgeeks.org/dnschef-penetration-testers-and-malware-analysts/
    """import socket
    from dnslib import DNSRecord
    UPSTREAM_DNS_SERVER = ('8.8.8.8, 53) # Google's public DNS server
    
    def forward_query(data, addr, sock):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            print("Forwarding query to upstream server...")
            upstream_sock.sendto(data, UPSTREAM_DNS_SERVER)
            response, upstream_sock.recvfrom(512)
            sock.sendto(response, addr)
            print("Response forwarded to client.")
    
    def dns_handler(data, addr, sock):
        print("Received query, forwarding to upstream...")
        forward_query(data, addr, sock)
    
    def main():
        ip = '127.0.0.3'
        port = 5354
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip, port))
        print(f" DNS server started on {ip}:{port}")
        try:
            while True:
                data, addr = sock.recvfrom(512)
                dns_handler(data, addr, sock)
        except KeyboardInterrupt:
            print("Shutting down DNS server")
        finally:
            sock.close()
    
    if _name_ == "__main__":
        main()"""