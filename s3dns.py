import socket
import logging
import threading
import time
import sys
import re
import os
import requests
import ipaddress
import dns.resolver
import dns.rcode
from helpers import color
from concurrent.futures import ThreadPoolExecutor



# developed by github.com/olizimmermann
# initial inspiration from https://www.youtube.com/user/CreatiiveCode
# https://www.ietf.org/rfc/rfc1035.txt # dns protocol


# Use S3DNSDetector for intercepting DNS requests
# Run it via python3 s3dns.py
# Not suited as default dns server, only for analyzing.
# Please check regularly on Github for latest updates

# configuration possible below

version = "0.0.6"
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
    
    # Add regex patterns if needed
    regex_patterns = [
       # AWS S3 - Virtual-hosted–style (global)
       r"[a-z0-9.-]+\.s3\.amazonaws\.com",
       r"[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com",
       r"[a-z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com",
   
       # AWS S3 - Virtual-hosted–style (China)
       r"[a-z0-9.-]+\.s3\.amazonaws\.com\.cn",
       r"[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com\.cn",
       r"[a-z0-9.-]+\.s3\.[a-z0-9-]+\.amazonaws\.com\.cn",
   
       # AWS S3 - Path-style (global + regional + China)
       r"s3\.amazonaws\.com",
       r"s3-[a-z0-9-]+\.amazonaws\.com",
       r"s3\.[a-z0-9-]+\.amazonaws\.com",
       r"s3\.amazonaws\.com\.cn",
       r"s3-[a-z0-9-]+\.amazonaws\.com\.cn",
       r"s3\.[a-z0-9-]+\.amazonaws\.com\.cn",
   
       # Google Cloud Storage - Virtual-hosted & path-style
       r"[a-z0-9._-]+\.storage\.googleapis\.com",
       r"storage\.googleapis\.com",
   
       # Azure Blob Storage
       r"[a-z0-9-]+\.blob\.core\.windows\.net",
   
       # DigitalOcean Spaces (optional)
       r"[a-z0-9.-]+\.[a-z0-9-]+\.digitaloceanspaces\.com",
   
       # Wasabi (optional)
       r"[a-z0-9.-]+\.s3\.[a-z0-9-]+\.wasabisys\.com",
       r"s3\.[a-z0-9-]+\.wasabisys\.com"
    ]

   # In case you need to add some hardcoded patterns
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

    # Add IP ranges to check against, automatically filled with AWS IP ranges
    ip_ranges = []

    def __init__(self, debug=False, bucket_file='buckets.txt'):
        self.debug = debug
        self.real_dns = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.bucket_file = bucket_file
        self.ip_ranges.extend(self.read_aws_ip_ranges())
        self.executor = ThreadPoolExecutor(max_workers=20)
        
    def dns_response(self, data, addr):
        """Extracting requested domain out of dns packet

        Args:
            data (bytes): DNS packet
            addr (tuple(ip,port)): address information

        Returns:
            bytes: dns answer packet
        """
        ip = addr[0]
        
        # use dns.message to extract domain
        try:
            dns_message = dns.message.from_wire(data)
            question = dns_message.question[0]
            domain = question.name.to_text()
        except Exception as e:
            print(f"Error extracting domain: {e}")
            sys.stdout.flush()
            fail_response = dns.message.make_response(dns_message)
            fail_response.set_rcode(dns.rcode.SERVFAIL)
            return fail_response.to_wire()
        

        domain = domain[:-1]
        domain_ip = color.bcolors.color_text(domain, color.bcolors.OKBLUE) + " requested by " + color.bcolors.color_text(ip, color.bcolors.OKGREEN)
        domain_ip_logger = domain + " requested by " + ip

        if self.debug:
            # logger.info(domain_ip_logger)
            print(domain_ip)
            sys.stdout.flush()

        # t = threading.Thread(target=self.s3dns_detector, args=(domain, ip, domain))
        # t.daemon = True
        # t.start()
        # _ = self.s3dns_detector(domain=domain, ip=ip, org_domain=domain)

        self.executor.submit(self.s3dns_detector, domain=domain, ip=ip, org_domain=domain)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_forward:
                dns_forward.settimeout(2)
                dns_forward.connect((self.real_dns, 53))
                dns_forward.send(data)
                return dns_forward.recv(512)
        except socket.timeout:
            if self.debug:
                print(f"{color.bcolors.FAIL}Timeout: No response from DNS server{color.bcolors.ENDC}")
                sys.stdout.flush()

        except Exception as e:
            if self.debug:
                print(f"{color.bcolors.FAIL}Error: {e}{color.bcolors.ENDC}")
                sys.stdout.flush()
        fail_response = dns.message.make_response(dns_message)
        fail_response.set_rcode(dns.rcode.SERVFAIL)
        return fail_response.to_wire()

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
                            sys.stdout.flush()
                        return
            # add domain to file
            with open(self.bucket_file, 'a') as f:
                f.write(f"{domain}\n")
                if self.debug:
                    print(f"{color.bcolors.OKGREEN}Domain {domain} added to bucket file{color.bcolors.ENDC}")
                    sys.stdout.flush()
            return

    def s3dns_detector(self, domain, ip=None, org_domain=None):
        """Detecting S3DNS

        Args:
            domain (str): domain to check
        """
        try:
            # Check if the domain matches any of the regex patterns
            regex_match = False
            for pattern in self.regex_patterns:
                if re.match(pattern, domain):
                    regex_match = True
                    break
            
            # Check if the domain matches any of the hardcoded patterns
            hardcoded_match = False
            if not regex_match:
                for pattern in self.patterns:
                    if pattern in domain:
                        hardcoded_match = True
                        break
            
            # Check if the domain is in the ip ranges
            ip_match = False
            ip_resolved = True
            if not regex_match and not hardcoded_match:
                if self.ip_ranges and len(self.ip_ranges) > 0:
                    try:
                        domain_ips = dns.resolver.resolve(domain, 'A')
                    except Exception as e:
                        if self.debug:
                            print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
                            sys.stdout.flush()
                        ip_resolved = False

                    if ip_resolved:
                        for ip_range in self.ip_ranges:
                            for domain_ip in domain_ips:
                                if self.is_ip_in_range_subnet(domain_ip, ip_range):
                                    ip_match = True
                                    if self.debug:
                                        print(f"{color.bcolors.OKGREEN}IP range detected: {ip_range}{color.bcolors.ENDC}")
                                        sys.stdout.flush()
                                    break


            if regex_match or hardcoded_match or ip_match or ('s3' in domain and domain.endswith('.amazonaws.com')):

                if ip_match:
                    ip_range_msg = f" (IP range)"
                else:
                    ip_range_msg = ""

                if org_domain == domain:
                    print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC}" + f"{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
                else:
                    print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC} {color.bcolors.WARNING}(Request: {org_domain}){color.bcolors.ENDC}" + f"{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
                sys.stdout.flush()
                logger.info(f"[{ip}] Bucket detected: {domain} (Request: {org_domain})" + ip_range_msg)
                self.add_to_bucket_file(domain)
                return True
            else:
                ret = self.detect_cname(domain=domain)
                cnames = []
                if ret:
                    cnames = ret
                for cname in cnames:
                    self.s3dns_detector(domain=cname, ip=ip, org_domain=org_domain)
                return False
        except Exception as e:
            print(f"Error: {e}")
            sys.stdout.flush()
            return False
    
    def detect_cname(self, domain):
        """Detecting CNAME records from domain Returns all cnames domains ()

        Args:
            domain (str): domain to check
        """
        cnames = []
        try:
            # Use dns.resolver to get CNAME records
            answers = self.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cnames.append(rdata.to_text())
            if cnames:
                if self.debug:
                    print(f"{color.bcolors.WARNING}CNAME records detected: {', '.join(cnames)}{color.bcolors.ENDC}")
                    sys.stdout.flush()
                    # logger.info(f"CNAME records detected: {', '.join(cnames)}")
                return cnames
            else:
                return False
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            if self.debug:
                print(f"{color.bcolors.FAIL}Domain {domain} does not exist{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"Domain {domain} does not exist")
            return False
        except dns.resolver.Timeout:
            if self.debug:
                print(f"{color.bcolors.FAIL}DNS query timed out for {domain}{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"DNS query timed out for {domain}")
            return False
        except Exception as e:
            if self.debug:
                print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"Error resolving {domain}: {e}")
            return False
        
    def is_ip_in_range_subnet(self, ip, subnet):
        """Check if an IP address is in a given subnet

        Args:
            ip (str): IP address to check
            subnet (str): Subnet in CIDR notation

        Returns:
            bool: True if the IP address is in the subnet, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(subnet, strict=False) # strict=False allows for non-canonical CIDR notation
            return ip in network
        except ValueError as e:
            print(f"Error checking IP range: {e}")
            sys.stdout.flush()
            return False
    
    def read_aws_ip_ranges(self, url="https://ip-ranges.amazonaws.com/ip-ranges.json"):
        """Read AWS IP ranges from the given URL

        Args:
            url (str): URL to read the IP ranges from
        """
        try:
            # use real dns for resolving
            ip = self.resolver.resolve(url, 'A')
            ip = ip[0].to_text()
            ip_url = f"https://{ip}/ip-ranges.json"
            headers = "Host: ip-ranges.amazonaws.com"
            response = requests.get(ip_url, timeout=5, headers=headers)
            data = response.json()
            ip_ranges = []
            for prefix in data['prefixes']:
                if prefix['service'] == 'S3':
                    ip_ranges.append(prefix['ip_prefix'])
            if self.debug:
                print(f"{color.bcolors.OKGREEN}AWS IP ranges read successfully{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"AWS IP ranges read successfully")
            return ip_ranges
        except Exception as e:
            print(f"Error reading AWS IP ranges: {e}")
            sys.stdout.flush()
            return []


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

    request_executor = ThreadPoolExecutor(max_workers=50)

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
    s3dns.resolver.nameservers = [dns_server]

    # Print the DNS server address
    print(f"Using DNS server: {color.bcolors.color_text(s3dns.real_dns, color.bcolors.OKGREEN)}")

    # flush print buffer
    sys.stdout.flush()
    while True:
        try:
            # Create a UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow address reuse
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
            request_executor.submit(s3dns.handler, data, addr, sock)
            sys.stdout.flush()
    
        except KeyboardInterrupt:
            print("\nExiting...")
            sock.close()
            break
        except Exception as e:
            print(f"Error: {e}")
