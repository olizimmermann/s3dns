import socket
import logging
import time
from datetime import datetime
import sys
import re
import os
import json
import requests
import ipaddress
import dns.resolver
import dns.rcode
from helpers import color
from concurrent.futures import ThreadPoolExecutor
import yaml



# developed by github.com/olizimmermann
# initial inspiration from https://www.youtube.com/user/CreatiiveCode
# https://www.ietf.org/rfc/rfc1035.txt # dns protocol


# Use S3DNSDetector for intercepting DNS requests
# Run it via python3 s3dns.py
# Not suited as default dns server, only for analyzing.
# Please check regularly on Github for latest updates

# configuration possible below

version = "0.1.0"
logo = r"""
   _____ ____    _____  _   _  _____   _____       _            _             
  / ____|___ \  |  __ \| \ | |/ ____| |  __ \     | |          | |            
 | (___   __) | | |  | |  \| | (___   | |  | | ___| |_ ___  ___| |_ ___  _ __ 
  \___ \ |__ <  | |  | | . ` |\___ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
  ____) |___) | | |__| | |\  |____) | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_____/|____/  |_____/|_| \_|_____/  |_____/ \___|\__\___|\___|\__\___/|_|                                                                            

developed by OZ          v{}
https://github.com/olizimmermann/s3dns
https://hub.docker.com/r/ozimmermann/s3dns
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
    """S3DNS class for detecting S3 buckets via DNS requests"""

    def __init__(self, debug=False, bucket_file='buckets.txt', aws_ip_ranges=True, azure_ip_ranges=True):
        self.debug = debug
        if self.debug:
            print(f"{color.bcolors.OKGREEN}Debug mode enabled{color.bcolors.ENDC}")
        self.real_dns = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.bucket_file = bucket_file
        self.ip_ranges = []
        if aws_ip_ranges:
            self.ip_ranges.extend(self.read_aws_ip_ranges())
        if azure_ip_ranges:
            self.ip_ranges.extend(self.read_azure_blob_ip_ranges()) # noisy
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.regex_patterns, self.patterns = self.load_patterns_from_folder("patterns")

        if self.debug:
            print(f"{color.bcolors.OKGREEN}Combined IP ranges: {len(self.ip_ranges)} ranges found{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Loaded patterns: {len(self.regex_patterns)} found{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Loaded hardcoded patterns: {len(self.patterns)} found{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Bucket file: {self.bucket_file}{color.bcolors.ENDC}")
    
    def _print(self, text):
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - {text}")

    def dns_response(self, data, addr):
        """Extracting requested domain out of dns packet

        Args:
            data (bytes): DNS packet
            addr (tuple(ip,port)): address information

        Returns:
            bytes: dns answer packet
        """
        ip = addr[0]
        
        try:
            dns_message = dns.message.from_wire(data)
            question = dns_message.question[0]
            domain = question.name.to_text()
        except Exception as e:
            self._print(f"Error extracting domain: {e}")
            sys.stdout.flush()
            fail_response = dns.message.make_response(dns_message)
            fail_response.set_rcode(dns.rcode.SERVFAIL)
            return fail_response.to_wire()
        

        domain = domain[:-1]
        domain_ip = color.bcolors.color_text(domain, color.bcolors.OKBLUE) + " requested by " + color.bcolors.color_text(ip, color.bcolors.OKGREEN)
        domain_ip_logger = domain + " requested by " + ip

        if self.debug:
            self._print(domain_ip)
            sys.stdout.flush()


        self.executor.submit(self.s3dns_detector, domain=domain, ip=ip, org_domain=domain)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_forward:
                dns_forward.settimeout(2)
                dns_forward.connect((self.real_dns, 53))
                dns_forward.send(data)
                return dns_forward.recv(512)
        except socket.timeout:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Timeout: No response from DNS server{color.bcolors.ENDC}")
                sys.stdout.flush()

        except Exception as e:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Error: {e}{color.bcolors.ENDC}")
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
                            self._print(f"{color.bcolors.OKGREEN}Domain {domain} already exists in bucket file{color.bcolors.ENDC}")
                            sys.stdout.flush()
                        return
            # add domain to file
            with open(self.bucket_file, 'a') as f:
                f.write(f"{domain}\n")
                if self.debug:
                    self._print(f"{color.bcolors.OKGREEN}Domain {domain} added to bucket file{color.bcolors.ENDC}")
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
                            self._print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
                            sys.stdout.flush()
                        ip_resolved = False

                    if ip_resolved:
                        for ip_range in self.ip_ranges:
                            for domain_ip in domain_ips:
                                if self.is_ip_in_range_subnet(domain_ip, ip_range):
                                    ip_match = True
                                    if self.debug:
                                        self._print(f"{color.bcolors.OKGREEN}IP range detected: {ip_range}{color.bcolors.ENDC}")
                                        sys.stdout.flush()
                                    break


            if regex_match or hardcoded_match or ip_match or ('s3' in domain and domain.endswith('.amazonaws.com')):

                if ip_match:
                    ip_range_msg = f" (IP range)"
                else:
                    ip_range_msg = ""

                if org_domain == domain:
                    self._print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC}" + f"{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
                else:
                    self._print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC} {color.bcolors.WARNING}(Request: {org_domain}){color.bcolors.ENDC}" + f"{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
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
            self._print(f"Error: {e}")
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
                    self._print(f"{color.bcolors.WARNING}CNAME records detected: {', '.join(cnames)}{color.bcolors.ENDC}")
                    sys.stdout.flush()
                    # logger.info(f"CNAME records detected: {', '.join(cnames)}")
                return cnames
            else:
                return False
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Domain {domain} does not exist{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"Domain {domain} does not exist")
            return False
        except dns.resolver.Timeout:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}DNS query timed out for {domain}{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"DNS query timed out for {domain}")
            return False
        except Exception as e:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
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
            self._print(f"Error checking IP range: {e}")
            sys.stdout.flush()
            return False
    
    def read_aws_ip_ranges(self, url="https://ip-ranges.amazonaws.com/ip-ranges.json", folder="ip_ranges/aws.json"):
        """Read AWS IP ranges from the given URL or local file

        Args:
            url (str): URL to read the IP ranges from
        """
        try:
            # use real dns for resolving
            domain = url.split('/')[2]
            ip = self.resolver.resolve(domain, 'A')
            
            ip = ip[0].to_text()
            ip_url = f"http://{ip}/ip-ranges.json"
            headers = {"Host": domain}
            try:
                # disable SSL warning
                requests.packages.urllib3.disable_warnings() # since we are using verify=False caused by the ip address
                response = requests.get(ip_url, timeout=5, headers=headers, verify=False)
                data = response.json()
            except Exception as e:
                # reading ip_ranges/aws.json
                try:
                    if os.path.exists(folder):
                        with open(folder, "r") as f:
                            data = json.load(f)
                    else:
                        raise FileNotFoundError(f"{folder} not found. Please download the AWS IP ranges JSON file.")
                except Exception as e:
                    self._print(f"Error reading {folder}: {e}")
                    sys.stdout.flush()
                    return []
                self._print(f"Not using AWS IP ranges")
                sys.stdout.flush()
                return []
            
            ip_ranges = []
            for prefix in data['prefixes']:
                if prefix['service'] == 'S3':
                    ip_ranges.append(prefix['ip_prefix'])
            if self.debug:
                self._print(f"{color.bcolors.OKGREEN}AWS IP ranges read successfully{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"AWS IP ranges read successfully")
                self._print(f"AWS IP ranges: {len(ip_ranges)} ranges found")
            return ip_ranges
        except Exception as e:
            self._print(f"Error reading AWS IP ranges: {e}")
            sys.stdout.flush()
            return []

    def read_azure_blob_ip_ranges(self, folder="ip_ranges/azure.json"):
        """Read Azure Blob Storage IP ranges from the given folder
        "systemService": "AzureStorage"

        Args:
            folder (str): Folder to read the IP ranges from
        """
        try:
            if os.path.exists(folder):
                with open(folder, "r") as f:
                    data = json.load(f)
            else:
                raise FileNotFoundError(f"{folder} not found. Please download the Azure IP ranges JSON file.")
            ip_ranges = []
            for prefix in data['values']:
                if prefix['properties']['systemService'] == 'AzureStorage':
                    if 'addressPrefixes' in prefix['properties']:
                        ip_ranges.extend(prefix['properties']['addressPrefixes'])
            if self.debug:
                self._print(f"{color.bcolors.OKGREEN}Azure IP ranges read successfully{color.bcolors.ENDC}")
                sys.stdout.flush()
                # logger.info(f"Azure IP ranges read successfully")
                self._print(f"Azure IP ranges: {len(ip_ranges)} ranges found")
            return ip_ranges
        except Exception as e:
            self._print(f"Error reading Azure IP ranges: {e}")
            sys.stdout.flush()
            return []

    def load_patterns_from_folder(self, folder_path="patterns"):
        """
        Reads all YAML files in the given folder.
        Files starting with 'regex_' are treated as regex patterns.
        Other files are treated as hardcoded patterns (plain hostnames).

        Returns:
            regex_patterns (list[str]), hardcoded_patterns (list[str])
        """
        regex_patterns = []
        hardcoded_patterns = []

        for filename in os.listdir(folder_path):
            if not filename.endswith((".yml", ".yaml")):
                continue  # skip non-YAML files

            full_path = os.path.join(folder_path, filename)
            with open(full_path, "r") as f:
                data = yaml.safe_load(f)

            if filename.startswith("regex_"):
                # Flatten all pattern lists in YAML file
                for patterns in data.values():
                    regex_patterns.extend(patterns)
            else:
                # For hardcoded patterns, expect a single key list
                for patterns in data.values():
                    hardcoded_patterns.extend(patterns)

        return regex_patterns, hardcoded_patterns


if __name__ == "__main__":
    # Initialize the S3DNS class
    debug = os.getenv("DEBUG", "false").lower() == "true"
    docker = os.getenv("DOCKER", "false").lower() == "true"

    aws_ip_ranges_var = os.getenv("AWS_IP_RANGES", "true").lower() == "true"
    azure_ip_ranges_var = os.getenv("AZURE_IP_RANGES", "true").lower() == "true"

    s3dns = S3DNS(debug=debug, aws_ip_ranges=aws_ip_ranges_var, azure_ip_ranges=azure_ip_ranges_var)

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
    print(f"{color.bcolors.OKBLUE}Running S3DNS Detector...\n{color.bcolors.ENDC}")
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
