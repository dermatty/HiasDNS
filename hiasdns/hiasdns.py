#! /usr/bin/python
import threading
import time, sys
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from threading import Thread
import random
import asyncio
import ssl
import socket
import socketserver

import gevent.lock
from dnslib import DNSRecord, QTYPE, RR, A, DNSHeader
from os.path import expanduser
import configparser
import logging
import logging.handlers
import json
from gevent.server import DatagramServer

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

BEST_SERVER = ('10.4.0.1', 53, 0.0)










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

def nameserver_testthread(testdomains, full_dns_dic, lock, timeout, logger):
    global BEST_SERVER
    try:
        maxtimeout = timeout
        full_dns_list = list(full_dns_dic.items())
        testdomains_q = []
        for td0 in testdomains:
            qname0 = dns.name.from_text(td0)
            q = dns.message.make_query(qname0, dns.rdatatype.A)
            testdomains_q.append(q)
        testdq_len = len(testdomains)
        
        while True:
            testdomain_q0 = testdomains_q[random.randint(0, testdq_len-1)]
            random_dns = random.choice(full_dns_list)
            ip = random_dns[0]
            port = int(random_dns[1]["port"])
            proto = random_dns[1]["proto"]
            #print(ip, port, proto)
            #print(testdomain_q0)
            
            t0 = time.time()
            # if proto.lower() == "udp":
            try:
                r = dns.query.udp(testdomain_q0, ip, port=port, timeout=maxtimeout).answer
            except (Exception, ):
                r = []
            
            rtt0 = time.time() - t0
            testlist = [ip for ip in full_dns_dic if full_dns_dic[ip]["rtt"] < 0.0]
            if not r:
                full_dns_dic[ip]["rtt"] = maxtimeout
            else:
                if testlist:
                    full_dns_dic[ip]["rtt"] = rtt0
                else:
                    full_dns_dic[ip]["rtt"] = full_dns_dic[ip]["rtt"] * 0.6 + rtt0 * 0.4
            
            dns_sorted = sorted([(dns0, full_dns_dic[dns0]["port"], full_dns_dic[dns0]["proto"],
                                      full_dns_dic[dns0]["rtt"]) for dns0 in full_dns_dic
                                     if full_dns_dic[dns0]["primary"] and full_dns_dic[dns0]["primary"] < timeout*0.8],
                                key=lambda idx: idx[3])
            if not dns_sorted:
                dns_sorted = sorted([(dns0, full_dns_dic[dns0]["port"], full_dns_dic[dns0]["proto"],
                                      full_dns_dic[dns0]["rtt"]) for dns0 in full_dns_dic
                                     if not full_dns_dic[dns0]["primary"]], key=lambda idx: idx[3])
            logger.debug(str(dns_sorted))
            with lock:
                BEST_SERVER = (dns_sorted[0][0], dns_sorted[0][1], dns_sorted[0][2])
            
            if len(testlist) > 0:
                to0 = 0.01
            else:
                to0 = maxtimeout
            time.sleep(to0)
    except Exception as e:
        logger.error("ERROR in nameserver_testthread: " + str(e))
        

def handle_query(data, addr, sock, logger):
    global BEST_SERVER

    # dns over tls geht so:
    ## https://github.com/melvilgit/dns-over-tls/blob/master/dnsovertls.py

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
        # with tlock:
        server, port, _ = BEST_SERVER #get_best_upstream_dns(primary_dns, backup_dns, full_dns_dic, tlock)
        logger.debug("forwarding to " + str(server) + ":" + str(port))
        try:
            upstream_sock.sendto(data, (server, port))
            response, _ = upstream_sock.recvfrom(512)
            #request = str(DNSRecord.parse(response)).split(";;")
            #print(request)
            sock.sendto(response, addr)
        except (Exception, ):
            pass

#gevent
class GeventDNSServer(DatagramServer):
    def setparams(self, logger):
        self.logger = logger

    def handle(self, data, address): # pylint:disable=method-hidden
        handle_query(data, address, self.socket, self.logger)

#asyncio
class AsyncioDNSServerProtocol:

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        server, port, _ = BEST_SERVER
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.sendto(data, (server, port))
            response, _ = upstream_sock.recvfrom(512)
        #print(DNSRecord.parse(response))
        self.transport.sendto(response, addr)



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
            print("_" * 80)

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

async def asyncio_main(this_dns_server):
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(AsyncioDNSServerProtocol,
        local_addr=this_dns_server)
    try:
        while True:
            await asyncio.sleep(3600)  # Serve for 1 hour.
    finally:
        transport.close()

# Idee: zum besten nicht besetzten primary server forwarden
def start():
    global BEST_SERVER
    # on client side:
    #  dig @127.0.0.1 -p 5853 orf.at
    #       or
    # nslookup -port=5853 orf.at localhost

    # tls sockets: https://gist.github.com/marshalhayes/ca9508f97d673b6fb73ba64a67b76ce8

    userhome = expanduser("~")
    maindir = userhome + "/.hiasdns/"
    
    # Init Logger
    logger = logging.getLogger("hdns")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(maindir + "hiasdns.log", mode="w")
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    logger.info("-" * 80)
    # set threading mode, default is python threading module
    try:
        tmode = sys.argv[1]
        if tmode.lower() not in ["gevent", "threading", "asyncio"]:
            tmode = "threading"
    except (Exception,):
        tmode = "threading"
    logger.debug("Set threading mode to " + tmode)
    
    # read config
    cfg_file = maindir + "config"
    try:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        
        bindaddress = str(cfg["GENERAL"]["bindaddress"])
        listenport = int(cfg["GENERAL"]["listenport"])
        assert 1024 < listenport <= 65535
        logger.info("Set bindaddress, port to: (" + bindaddress + ", " + str(listenport) + ")")
        
        testdomains = json.loads(cfg["GENERAL"]["testdomains"])
        logger.info("Set testdomains to : " + str(testdomains))
        
        i = 1
        primary_dns = {}
        while True:
            try:
                ip0 = str(cfg["PRIMARYDNS" + str(i)]["ip"])
                port0 = int(cfg["PRIMARYDNS" + str(i)]["port"])
                assert 1024 < listenport <= 65535
                proto0 = str(cfg["PRIMARYDNS" + str(i)]["proto"])
            except (Exception, ):
                break
            primary_dns[ip0] = {"port": port0, "proto": proto0, "rtt": -1.0, "primary": True}
            i += 1
        if i==1:
            logger.error("Config ERROR: no primary nameservers given, exiting ...")
        logger.info("Set primary nameservers to : " + str(primary_dns))
        i = 1
        backup_dns = {}
        while True:
            try:
                ip0 = str(cfg["BACKUPDNS" + str(i)]["ip"])
                port0 = int(cfg["BACKUPDNS" + str(i)]["port"])
                assert 1024 < listenport <= 65535
                proto0 = str(cfg["BACKUPDNS" + str(i)]["proto"])
            except (Exception,):
                break
            backup_dns[ip0] = {"port": port0, "proto": proto0, "rtt": -1.0, "primary": False}
            i += 1
    except Exception as e:
        logger.error(str(e) + ", exiting ...")
        sys.exit()
    logger.info("Set backup nameservers to : " + str(backup_dns))


    
    MAXTIMEOUT = 5.0
    
    # start MP process for testing nameservers on testdomains
    full_dns_dic = primary_dns | backup_dns
    tlock = threading.Lock()
    ntt = threading.Thread(target=nameserver_testthread, args=(testdomains, full_dns_dic, tlock, MAXTIMEOUT, logger))
    ntt.daemon = True
    ntt.start()
    logger.debug("Started + initializing testthread ...")
    t0 = time.time()
    while True:
        with tlock:
            if len([ip for ip in full_dns_dic if full_dns_dic[ip]["rtt"] < 0.0]) == 0:
                break
        time.sleep(0.1)
    logger.debug("Testthread initialized after " + str(round(time.time() - t0, 2)) + " sec!")
    logger.debug("Full nameserver dict. is: " + str(full_dns_dic))

    
    # start main Thread

    this_dns_server = (bindaddress, listenport)
    this_dns_server_str = bindaddress + ":" + str(listenport)

    if tmode == "gevent":
        logger.info("DNS gevent server started on " + str(this_dns_server))
        es = GeventDNSServer(this_dns_server_str)
        es.setparams(logger)
        es.serve_forever()
    elif tmode == "asyncio":
        logger.info("DNS asyncio server started on " + str(this_dns_server))
        asyncio.run(asyncio_main(this_dns_server))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(this_dns_server)
        logger.info("DNS threading server started on " + str(this_dns_server))
        while True:
            data, addr = sock.recvfrom(1024)
            t = threading.Thread(target=handle_query, args=(data, addr, sock, logger,))
            t.daemon = True
            t.start()









    
    # CONTEXT = ssl.create_default_context()
    # CONTEXT = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    # CONTEXT.load_verify_locations("/home/stephan/CA_ssl/rootCA.pem")
    # conn = CONTEXT.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname="dns.quad9.net")
    # conn.connect(("9.9.9.9", 853))
    # print("connected")

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