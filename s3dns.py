import socket
import logging
from typing import Annotated
# from rich import print as rprint
import threading
import time
import sys
import re
import os
import dns.resolver
from helpers import color


# developed by github.com/olizimmermann
# initial inspiration from https://www.youtube.com/user/CreatiiveCode
# https://www.ietf.org/rfc/rfc1035.txt # dns protocol


# Use S3DNSDetector for intercepting DNS requests
# Run it via python3 s3dns.py
# Not suited as default dns server, only for analyzing.
# Please check regulary on Github for latest updates

# configuration possible below

version = "0.0.2"
logo = r"""
   _____ ____    _____  _   _  _____   _____       _            _             
  / ____|___ \  |  __ \| \ | |/ ____| |  __ \     | |          | |            
 | (___   __) | | |  | |  \| | (___   | |  | | ___| |_ ___  ___| |_ ___  _ __ 
  \___ \ |__ <  | |  | | . ` |\___ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ____) |___) | | |__| | |\  |____) | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_____/|____/  |_____/|_| \_|_____/  |_____/ \___|\__\___|\___|\__\___/|_|                                                                            

developed by OZ          v{}
github.com/olizimmermann/s3dns

""".format(version)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("s3dns.log")
    ]
)
logger = logging.getLogger(__name__)

class S3DNS:

    s3_regex_patterns = [
        r"s3-[a-z0-9]+\.s3\.amazonaws\.com",
        r"s3-[a-z0-9]+\.s3-[a-z0-9]+\.amazonaws\.com",
        r"[a-z0-9]+\.s3\.amazonaws\.com",
        r"[a-z0-9]+\.s3-[a-z0-9]+\.amazonaws\.com",
        r"[a-z0-9]+\.s3\.amazonaws\.com\.cn",
        r"[a-z0-9]+\.s3-[a-z0-9]+\.amazonaws\.com\.cn",
        r"([a-z0-9.-]+)\.s3(?:[-a-z0-9]*)?\.amazonaws\.com(?:/[^\s]*)?",
        r"(?:([a-z0-9.-]+)\.s3(?:[-a-z0-9]*)\.amazonaws\.com|s3(?:[-a-z0-9]*)\.amazonaws\.com/([a-z0-9.-]+))(?:/[^\s]*)?",
        r"([a-z0-9-]+)\.blob\.core\.windows\.net(?:/[^\s]*)?",
        r"([a-z0-9._-]+)\.storage\.googleapis\.com(?:/[^\s]*)?"
    ]

    patterns = [
        "s3-us-west-1.amazonaws.com",
        "s3-us-west-2.amazonaws.com",
        "s3-us-east-1.amazonaws.com",
        "s3-us-east-2.amazonaws.com",
        "s3-eu-west-1.amazonaws.com",
        "s3-eu-west-2.amazonaws.com",
        "s3-eu-west-3.amazonaws.com",
        "s3-eu-central-1.amazonaws.com",
        "s3-ap-southeast-1.amazonaws.com",
        "s3-ap-southeast-2.amazonaws.com",
        "s3-ap-south-1.amazonaws.com",
        "s3-ap-northeast-1.amazonaws.com",
        "s3-ap-northeast-2.amazonaws.com",
        "s3-ca-central-1.amazonaws.com",
        "s3-sa-east-1.amazonaws.com",
        "s3.amazonaws.com",]


    def __init__(self, debug=False, bucket_file='buckets.txt'):
        self.debug = debug
        self.real_dns = None
        self.bucket_file = bucket_file
        

    def dns_response(self, data, addr):
        """Extracting requested domain out of dns packet

        Args:
            data (bytes): DNS packet
            addr (tupel(ip,port)): address information

        Returns:
            bytes: dns answer packet
        """
        ip = addr[0]
        # Extract the domain from the DNS packet
        # The DNS packet format is as follows:
        # 0-1: Transaction ID
        # 2-3: Flags
        # 4-5: Questions
        # 6-7: Answer RRs
        # 8-9: Authority RRs
        # 10-11: Additional RRs
        # 12+: Questions (QNAME, QTYPE, QCLASS)
        #
        # state = 0
        # expected_length = 0
        # domain_str = ''
        # domain_parts = []
        # x = 0
        # y = 0
        # for byte in data[12:]:
        #     if state == 1:
        #         if byte != 0:
        #             domain_str += chr(byte)
        #         x += 1
        #         if x == expected_length:
        #             domain_parts.append(domain_str)
        #             domain_str = ''
        #             state = 0
        #             x = 0
        #         if byte == 0:
        #             domain_parts.append(domain_str)
        #             break

        #     else:
        #         state = 1
        #         expected_length = byte
        #     y += 1 # QNAME and QTYPE

        # use dns.message to extract domain
        try:
            dns_message = dns.message.from_wire(data)
            question = dns_message.question[0]
            domain = question.name.to_text()
            domain_parts = domain.split('.')
        except Exception as e:
            print(f"Error extracting domain: {e}")
            return data
        

        domain_merge = ".".join(domain_parts[:-1])
        domain_merge_ip = color.bcolors.color_text(domain_merge, color.bcolors.OKBLUE) + " requested by " + color.bcolors.color_text(ip, color.bcolors.OKGREEN)
        domain_merge_ip_logger = domain_merge + " requested by " + ip
        if self.debug:
            # logger.info(domain_merge_ip_logger)
            print(domain_merge_ip)
        _ = self.s3dns_detector(domain_merge)

        dns_forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_forward.connect((self.real_dns, 53))
        dns_forward.send(data)
        return dns_forward.recv(512)

    def handler(self,data,addr,sock):
        """Handling DNS traffic

        Args:
            data (bytes): DNS packet
            addr (tupel(ip,port)): address information
            sock (socket): current socket which listens as dns

        Returns:
            int: 1 without exceptions
        """
        try:
            answer = self.dns_response(data, addr)
            sock.sendto(answer, addr)
        except:
            return 0
        return 1
    
    def add_to_bucket_file(self, domain):
        """Adding domain to bucket file

        Args:
            domain (str): domain to add
        """
        # check if file exists
        if not os.path.exists(self.bucket_file):
            # create file
            with open(self.bucket_file, 'w') as f:
                f.write(f"{domain}\n")
        else:
            # check if domain already exists
            with open(self.bucket_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if domain in line:
                        if self.debug:
                            print(f"{color.bcolors.OKGREEN}Domain {domain} already exists in bucket file{color.bcolors.ENDC}")
                        return
            # add domain to file
            with open(self.bucket_file, 'a') as f:
                f.write(f"{domain}\n")
                if self.debug:
                    print(f"{color.bcolors.OKGREEN}Domain {domain} added to bucket file{color.bcolors.ENDC}")
            return

    def s3dns_detector(self, domain):
        """Detecting S3DNS

        Args:
            domain (str): domain to check
        """
        try:
            # Check if the domain is a valid S3 bucket URL
            regex_match = False
            for pattern in self.s3_regex_patterns:
                # print(f"Checking pattern: {pattern} against domain: {domain}")
                if re.match(pattern, domain):
                    # print(f"{color.bcolors.OKGREEN}S3 Bucket detected: {domain}{color.bcolors.ENDC}")
                    regex_match = True
                    break

            if ('s3-' in domain and domain.endswith('.amazonaws.com')) or regex_match or any(pattern in domain for pattern in self.patterns):
                print(f"{color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC}")
                sys.stdout.flush()
                logger.info(f"Bucket detected: {domain}")
                self.add_to_bucket_file(domain)
                return True
            else:
                ret = self.detect_cname(domain)
                cnames = []
                if ret:
                    cnames = ret
                for cname in cnames:
                    self.s3dns_detector(cname)
                return False
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def detect_cname(self, domain):
        """Detecting CNAME records from domain Returns all cnames domains ()

        Args:
            domain (str): domain to check
        """
        cnames = []
        try:
            # Use dns.resolver to get CNAME records
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cnames.append(rdata.to_text())
            if cnames:
                if self.debug:
                    print(f"{color.bcolors.WARNING}CNAME records detected: {', '.join(cnames)}{color.bcolors.ENDC}")
                    # logger.info(f"CNAME records detected: {', '.join(cnames)}")
                return cnames
            else:
                return False
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            if self.debug:
                print(f"{color.bcolors.FAIL}Domain {domain} does not exist{color.bcolors.ENDC}")
                # logger.info(f"Domain {domain} does not exist")
            return False
        except dns.resolver.Timeout:
            if self.debug:
                print(f"{color.bcolors.FAIL}DNS query timed out for {domain}{color.bcolors.ENDC}")
                # logger.info(f"DNS query timed out for {domain}")
            return False
        except Exception as e:
            if self.debug:
                print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
                # logger.info(f"Error resolving {domain}: {e}")
            return False

        



if __name__ == "__main__":
    # Initialize the S3DNS class
    debug_var = os.getenv("DEBUG")
    docker_var = os.getenv("DOCKER")
    if docker_var:
        docker = True
    else:
        docker = False

    if debug_var:
        debug = True
    else:
        debug = False
    s3dns = S3DNS(debug=debug)

    # Print the logo
    print(logo)

    # Get the DNS server IP address
    local_dns_server_ip = '0.0.0.0'
    if not docker:
        local_dns_server_ip_input = input(f"Enter local DNS server address (default: {local_dns_server_ip}): ")
    else:
        local_dns_server_ip_input = os.getenv("LOCAL_DNS_SERVER_IP", '0.0.0.0')
                                              
    if local_dns_server_ip_input:
        local_dns_server_ip = local_dns_server_ip_input
    # Validate the IP address format
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not ip_pattern.match(local_dns_server_ip):
        print(f"Invalid IP address format: {local_dns_server_ip}")
        sys.exit(1)
    
    # Get the DNS server address from the user
    if not docker:
        dns_server = input(f"Enter real DNS server address (default: 1.1.1.1): ")
    else:
        dns_server = os.getenv('REAL_DNS_SERVER_IP', '1.1.1.1')

    if not dns_server:
        dns_server = '1.1.1.1'

    # bucket file
    if not docker:
        bucket_file = input(f"Enter bucket file path (default: buckets.txt): ")
    else:
        bucket_file = os.getenv('BUCKET_FILE', 'buckets.txt')
    if not bucket_file:
        bucket_file = 'buckets.txt'

    s3dns.bucket_file = bucket_file


    # Validate the DNS server address format
    dns_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not dns_pattern.match(dns_server):
        print(f"Invalid DNS server address format: {dns_server}")
        sys.exit(1)

    s3dns.real_dns = dns_server

    # Print the DNS server address
    print(f"Using DNS server: {color.bcolors.color_text(s3dns.real_dns, color.bcolors.OKGREEN)}")

    # flush print buffer
    sys.stdout.flush()
    while True:
        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((local_dns_server_ip, 53))
            print(f"Listening on {color.bcolors.color_text(local_dns_server_ip, color.bcolors.OKGREEN)}:53")
            break
        except Exception as e:
            print(f"Error binding to {local_dns_server_ip}:53. Retrying...")
            time.sleep(5)
    
    # Print a message indicating that the script is running
    print(f"{color.bcolors.OKBLUE}Running S3DNS Detector...{color.bcolors.ENDC}")
    sys.stdout.flush()
    while True:
        try:
            # Receive data from the socket
            data, addr = sock.recvfrom(512)
            
            # Handle the DNS request in a separate thread
            t = threading.Thread(target=s3dns.handler, args=(data, addr, sock))
            t.daemon = True
            t.start()
            sys.stdout.flush()


        except KeyboardInterrupt:
            print("\nExiting...")
            sock.close()
            break
        except Exception as e:
            print(f"Error: {e}")
