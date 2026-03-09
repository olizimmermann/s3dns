import socket
import logging
import time
import struct
from datetime import datetime
import sys
import re
import os
import json
import requests
import ipaddress
import threading
import dns.resolver
import dns.rcode
from helpers import color
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, OrderedDict
import yaml



# developed by github.com/olizimmermann
# initial inspiration from https://www.youtube.com/user/CreatiiveCode
# https://www.ietf.org/rfc/rfc1035.txt # dns protocol


# Use S3DNSDetector for intercepting DNS requests
# Run it via python3 s3dns.py
# Not suited as default dns server, only for analyzing.
# Please check regularly on Github for latest updates

# configuration possible below

version = "0.2.2"
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


class _DNSCache:
    """Thread-safe LRU DNS response cache with TTL-based expiration.

    Entries are keyed by (name, rdtype, rdclass) so A and AAAA queries are
    cached independently.  When a cached response is returned, the transaction
    ID is rewritten to match the incoming query so the client accepts it.
    TTL decrement is not applied — entries are valid until they expire.
    """

    def __init__(self, max_size):
        self.max_size = max_size
        self._store = OrderedDict()   # key -> (response_bytes, expire_at)
        self._lock = threading.Lock()

    @staticmethod
    def _key(dns_message):
        if dns_message.question:
            q = dns_message.question[0]
            return (q.name.to_text(), q.rdtype, q.rdclass)
        return None

    def get(self, dns_message):
        """Return a cached response with a patched transaction ID, or None."""
        key = self._key(dns_message)
        if not key:
            return None
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            response_bytes, expire_at = entry
            if time.time() >= expire_at:
                del self._store[key]
                return None
            self._store.move_to_end(key)
            # Rewrite the first two bytes (transaction ID) to match this query
            return struct.pack('>H', dns_message.id) + response_bytes[2:]

    def put(self, dns_message, response_bytes, ttl):
        """Store a response. Evicts the least-recently-used entry when full."""
        if ttl <= 0 or not response_bytes:
            return
        key = self._key(dns_message)
        if not key:
            return
        with self._lock:
            self._store[key] = (response_bytes, time.time() + ttl)
            self._store.move_to_end(key)
            while len(self._store) > self.max_size:
                self._store.popitem(last=False)


class S3DNS:
    """S3DNS class for detecting S3 buckets via DNS requests"""

    def __init__(self, debug=False, bucket_file='buckets.txt', aws_ip_ranges=True,
                 azure_ip_ranges=True, rate_limit=100, max_cname_depth=10, cache_size=1000):
        self.debug = debug
        if self.debug:
            print(f"{color.bcolors.OKGREEN}Debug mode enabled{color.bcolors.ENDC}")
        self.real_dns = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.bucket_file = bucket_file
        self.rate_limit = rate_limit          # max DNS requests per second per client IP (0 = disabled)
        self.max_cname_depth = max_cname_depth

        # Thread-safety for bucket file writes and in-memory dedup
        self._bucket_lock = threading.Lock()
        self._found_buckets = set()

        # Rate limiting state: ip -> list of request timestamps within the last second
        self._rate_lock = threading.Lock()
        self._rate_counts = defaultdict(list)

        # Response cache (None = disabled)
        self._cache = _DNSCache(cache_size) if cache_size > 0 else None

        self.ip_ranges = []
        if aws_ip_ranges:
            self.ip_ranges.extend(self.read_aws_ip_ranges())
        if azure_ip_ranges:
            self.ip_ranges.extend(self.read_azure_blob_ip_ranges())

        # Pre-compute network objects once; split by family for AAAA support
        self._ip4_networks = []
        self._ip6_networks = []
        for r in self.ip_ranges:
            try:
                net = ipaddress.ip_network(r, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    self._ip4_networks.append(net)
                else:
                    self._ip6_networks.append(net)
            except ValueError as e:
                self._print(f"Invalid IP range skipped: {r} ({e})")

        self.executor = ThreadPoolExecutor(max_workers=20)
        # Semaphore caps pending detection tasks to prevent unbounded queue growth
        self._semaphore = threading.BoundedSemaphore(200)
        self.regex_patterns, self.patterns = self.load_patterns_from_folder("patterns")

        if self.debug:
            print(f"{color.bcolors.OKGREEN}IPv4 networks: {len(self._ip4_networks)}, IPv6 networks: {len(self._ip6_networks)}{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Loaded patterns: {len(self.regex_patterns)} found{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Loaded hardcoded patterns: {len(self.patterns)} found{color.bcolors.ENDC}")
            print(f"{color.bcolors.OKGREEN}Bucket file: {self.bucket_file}{color.bcolors.ENDC}")
            if self.rate_limit:
                print(f"{color.bcolors.OKGREEN}Rate limit: {self.rate_limit} req/s per IP{color.bcolors.ENDC}")
            if self._cache:
                print(f"{color.bcolors.OKGREEN}Cache: enabled (max {cache_size} entries){color.bcolors.ENDC}")
            else:
                print(f"{color.bcolors.OKGREEN}Cache: disabled{color.bcolors.ENDC}")

    def _print(self, text):
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - {text}")

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _is_rate_limited(self, ip):
        """Return True if the client IP has exceeded the configured rate limit."""
        if not self.rate_limit:
            return False
        now = time.time()
        with self._rate_lock:
            self._rate_counts[ip] = [t for t in self._rate_counts[ip] if now - t < 1.0]
            if len(self._rate_counts[ip]) >= self.rate_limit:
                return True
            self._rate_counts[ip].append(now)
            return False

    # ------------------------------------------------------------------
    # Detection task submission
    # ------------------------------------------------------------------

    def _submit_detection(self, domain, ip, org_domain):
        """Submit a detection task with backpressure via semaphore.

        If the queue is full the DNS request is still forwarded normally;
        only the passive analysis is dropped.
        """
        if not self._semaphore.acquire(blocking=False):
            if self.debug:
                self._print(f"{color.bcolors.WARNING}Detection queue full, dropping analysis for: {domain}{color.bcolors.ENDC}")
            return

        def run():
            try:
                self.s3dns_detector(domain=domain, ip=ip, org_domain=org_domain)
            finally:
                self._semaphore.release()

        self.executor.submit(run)

    # ------------------------------------------------------------------
    # DNS message helpers
    # ------------------------------------------------------------------

    def _extract_domain(self, data):
        """Parse DNS wire data into a message and domain string.

        Returns (dns_message, domain) where either may be None on failure.
        """
        dns_message = None
        domain = None
        try:
            dns_message = dns.message.from_wire(data)
            domain = dns_message.question[0].name.to_text().rstrip('.')
        except Exception as e:
            self._print(f"Error parsing DNS message: {e}")
        return dns_message, domain

    def _get_response_ttl(self, response_bytes):
        """Return the minimum TTL found in the answer/authority sections."""
        try:
            msg = dns.message.from_wire(response_bytes)
            ttls = [rr.ttl for section in (msg.answer, msg.authority) for rr in section]
            return min(ttls) if ttls else 0
        except Exception:
            return 0

    def _cache_get(self, dns_message):
        if self._cache and dns_message:
            return self._cache.get(dns_message)
        return None

    def _cache_put(self, dns_message, response_bytes):
        if self._cache and dns_message and response_bytes:
            ttl = self._get_response_ttl(response_bytes)
            self._cache.put(dns_message, response_bytes, ttl)

    # ------------------------------------------------------------------
    # Upstream forwarding
    # ------------------------------------------------------------------

    def _forward_udp(self, data):
        """Forward a DNS query to the upstream resolver over UDP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect((self.real_dns, 53))
                s.send(data)
                return s.recv(4096)
        except socket.timeout:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Timeout: No response from DNS server (UDP){color.bcolors.ENDC}")
        except Exception as e:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}UDP forward error: {e}{color.bcolors.ENDC}")
        return None

    def _forward_tcp(self, data):
        """Forward a DNS query to the upstream resolver over TCP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.real_dns, 53))
                s.sendall(struct.pack('>H', len(data)) + data)
                raw_len = self._recv_exact(s, 2)
                if not raw_len:
                    return None
                length = struct.unpack('>H', raw_len)[0]
                return self._recv_exact(s, length)
        except socket.timeout:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Timeout: No response from DNS server (TCP){color.bcolors.ENDC}")
        except Exception as e:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}TCP forward error: {e}{color.bcolors.ENDC}")
        return None

    @staticmethod
    def _recv_exact(sock, n):
        """Read exactly n bytes from a stream socket, or return None on EOF."""
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ------------------------------------------------------------------
    # UDP path
    # ------------------------------------------------------------------

    def dns_response(self, data, addr):
        """Process a UDP DNS request: parse, cache-check, forward, cache-store.

        Returns bytes to send back to the client, or None if the message
        could not be parsed at all.
        """
        ip = addr[0]
        dns_message, domain = self._extract_domain(data)

        if dns_message is None:
            return None

        if domain is None:
            fail = dns.message.make_response(dns_message)
            fail.set_rcode(dns.rcode.SERVFAIL)
            return fail.to_wire()

        if self.debug:
            label = color.bcolors.color_text(domain, color.bcolors.OKBLUE) + \
                    " requested by " + color.bcolors.color_text(ip, color.bcolors.OKGREEN)
            self._print(label)
            sys.stdout.flush()

        cached = self._cache_get(dns_message)
        if cached:
            if self.debug:
                self._print(f"Cache hit: {domain}")
            return cached

        self._submit_detection(domain=domain, ip=ip, org_domain=domain)

        response = self._forward_udp(data)
        self._cache_put(dns_message, response)
        if response:
            return response

        fail = dns.message.make_response(dns_message)
        fail.set_rcode(dns.rcode.SERVFAIL)
        return fail.to_wire()

    def handler(self, data, addr, sock):
        """Handle a single UDP DNS request.

        Args:
            data (bytes): DNS packet
            addr (tuple(ip, port)): address information
            sock (socket): UDP socket listening as DNS

        Returns:
            int: 1 on success, 0 on failure or rate-limit drop
        """
        ip = addr[0]
        if self._is_rate_limited(ip):
            if self.debug:
                self._print(f"{color.bcolors.WARNING}Rate limit exceeded for {ip}, dropping request{color.bcolors.ENDC}")
            return 0
        try:
            answer = self.dns_response(data, addr)
            if answer:
                sock.sendto(answer, addr)
        except Exception:
            return 0
        return 1

    # ------------------------------------------------------------------
    # TCP path
    # ------------------------------------------------------------------

    def _handle_tcp_client(self, conn, addr):
        """Handle a single TCP DNS connection."""
        ip = addr[0]
        try:
            if self._is_rate_limited(ip):
                if self.debug:
                    self._print(f"{color.bcolors.WARNING}Rate limit exceeded for {ip} (TCP), dropping{color.bcolors.ENDC}")
                return

            raw_len = self._recv_exact(conn, 2)
            if not raw_len:
                return
            length = struct.unpack('>H', raw_len)[0]
            data = self._recv_exact(conn, length)
            if not data:
                return

            dns_message, domain = self._extract_domain(data)
            if dns_message is None:
                return

            if domain is None:
                fail = dns.message.make_response(dns_message)
                fail.set_rcode(dns.rcode.SERVFAIL)
                wire = fail.to_wire()
                conn.sendall(struct.pack('>H', len(wire)) + wire)
                return

            if self.debug:
                self._print(f"[TCP] {color.bcolors.color_text(domain, color.bcolors.OKBLUE)}"
                            f" requested by {color.bcolors.color_text(ip, color.bcolors.OKGREEN)}")
                sys.stdout.flush()

            cached = self._cache_get(dns_message)
            if cached:
                if self.debug:
                    self._print(f"Cache hit (TCP): {domain}")
                conn.sendall(struct.pack('>H', len(cached)) + cached)
                return

            self._submit_detection(domain=domain, ip=ip, org_domain=domain)

            # Clients connect over TCP typically because the UDP response was
            # truncated, so forward upstream over TCP to get the full answer.
            response = self._forward_tcp(data)
            if response:
                self._cache_put(dns_message, response)
                conn.sendall(struct.pack('>H', len(response)) + response)
            else:
                fail = dns.message.make_response(dns_message)
                fail.set_rcode(dns.rcode.SERVFAIL)
                wire = fail.to_wire()
                conn.sendall(struct.pack('>H', len(wire)) + wire)

        except Exception as e:
            if self.debug:
                self._print(f"TCP client error ({ip}): {e}")
        finally:
            conn.close()

    def start_tcp_server(self, host, port=53):
        """Bind a TCP/53 socket and start accepting clients in a daemon thread.

        The bind happens synchronously so caller gets an immediate error on failure.
        Returns the background thread.
        """
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_sock.bind((host, port))
        tcp_sock.listen(128)

        def serve():
            while True:
                try:
                    conn, addr = tcp_sock.accept()
                    conn.settimeout(5)
                    threading.Thread(
                        target=self._handle_tcp_client,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.debug:
                        self._print(f"TCP accept error: {e}")

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        return t

    # ------------------------------------------------------------------
    # Bucket file
    # ------------------------------------------------------------------

    def add_to_bucket_file(self, domain):
        """Add a domain to the bucket file (thread-safe, session-deduped).

        Args:
            domain (str): domain to add
        """
        with self._bucket_lock:
            if domain in self._found_buckets:
                if self.debug:
                    self._print(f"{color.bcolors.OKGREEN}Domain {domain} already recorded{color.bcolors.ENDC}")
                    sys.stdout.flush()
                return
            self._found_buckets.add(domain)
            with open(self.bucket_file, 'a') as f:
                f.write(f"{domain}\n")
            if self.debug:
                self._print(f"{color.bcolors.OKGREEN}Domain {domain} added to bucket file{color.bcolors.ENDC}")
                sys.stdout.flush()

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    def s3dns_detector(self, domain, ip=None, org_domain=None, _depth=0):
        """Detect cloud storage bucket domains via pattern and IP-range matching.

        Args:
            domain (str): domain to check
            _depth (int): current CNAME recursion depth (internal use only)
        """
        if _depth > self.max_cname_depth:
            if self.debug:
                self._print(f"{color.bcolors.WARNING}Max CNAME depth ({self.max_cname_depth}) reached for {domain}{color.bcolors.ENDC}")
            return False

        try:
            # 1. Regex patterns (short-circuits on first match)
            regex_match = any(re.match(pattern, domain) for pattern in self.regex_patterns)

            # 2. Hardcoded hostname substring patterns
            hardcoded_match = False
            if not regex_match:
                hardcoded_match = any(pattern in domain for pattern in self.patterns)

            # 3. IP-range check for both A (IPv4) and AAAA (IPv6) records
            ip_match = False
            if not regex_match and not hardcoded_match and (self._ip4_networks or self._ip6_networks):
                for rdtype in ('A', 'AAAA'):
                    if ip_match:
                        break
                    try:
                        resolved = dns.resolver.resolve(domain, rdtype)
                        for rdata in resolved:
                            ip_obj = ipaddress.ip_address(str(rdata))
                            networks = self._ip4_networks if ip_obj.version == 4 else self._ip6_networks
                            for net in networks:
                                if ip_obj in net:
                                    ip_match = True
                                    if self.debug:
                                        self._print(f"{color.bcolors.OKGREEN}IP range match: {ip_obj} in {net}{color.bcolors.ENDC}")
                                        sys.stdout.flush()
                                    break
                            if ip_match:
                                break
                    except Exception as e:
                        if self.debug:
                            self._print(f"{color.bcolors.FAIL}Error resolving {domain} {rdtype}: {e}{color.bcolors.ENDC}")
                            sys.stdout.flush()

            if regex_match or hardcoded_match or ip_match:
                # For name-based matches, check whether the domain actually resolves.
                # NXDOMAIN on a cloud-storage pattern means the DNS record is dangling —
                # an attacker could register the missing bucket and claim the subdomain.
                # Skip this check for pure IP-range hits (path-style endpoints always resolve).
                takeover_possible = False
                if regex_match or hardcoded_match:
                    try:
                        dns.resolver.resolve(domain, 'A')
                    except dns.resolver.NXDOMAIN:
                        takeover_possible = True
                    except Exception:
                        pass  # timeout / SERVFAIL — inconclusive, treat as normal hit

                ip_range_msg = " (IP range)" if ip_match else ""

                if takeover_possible:
                    if org_domain == domain:
                        self._print(f"[{ip}] {color.bcolors.WARNING}Possible takeover: {domain}{color.bcolors.ENDC} {color.bcolors.FAIL}(NXDOMAIN — bucket name may be unclaimed){color.bcolors.ENDC}")
                    else:
                        self._print(f"[{ip}] {color.bcolors.WARNING}Possible takeover: {domain}{color.bcolors.ENDC} {color.bcolors.FAIL}(NXDOMAIN — bucket name may be unclaimed){color.bcolors.ENDC} {color.bcolors.WARNING}(Request: {org_domain}){color.bcolors.ENDC}")
                    sys.stdout.flush()
                    logger.warning(f"[{ip}] Possible takeover: {domain} (Request: {org_domain}) — NXDOMAIN on cloud storage pattern")
                else:
                    if org_domain == domain:
                        self._print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC}{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
                    else:
                        self._print(f"[{ip}] {color.bcolors.FAIL}Bucket detected: {domain}{color.bcolors.ENDC} {color.bcolors.WARNING}(Request: {org_domain}){color.bcolors.ENDC}{color.bcolors.OKBLUE}{ip_range_msg}{color.bcolors.ENDC}")
                    sys.stdout.flush()
                    logger.info(f"[{ip}] Bucket detected: {domain} (Request: {org_domain}){ip_range_msg}")

                self.add_to_bucket_file(domain)
                return True
            else:
                cnames = self.detect_cname(domain=domain) or []
                for cname in cnames:
                    self.s3dns_detector(domain=cname, ip=ip, org_domain=org_domain, _depth=_depth + 1)
                return False

        except Exception as e:
            self._print(f"Error: {e}")
            sys.stdout.flush()
            return False

    def detect_cname(self, domain):
        """Return CNAME targets for the given domain, or False if none exist.

        Args:
            domain (str): domain to check
        """
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            # Strip trailing dots from CNAME targets
            cnames = [rdata.to_text().rstrip('.') for rdata in answers]
            if cnames:
                if self.debug:
                    self._print(f"{color.bcolors.WARNING}CNAME records detected: {', '.join(cnames)}{color.bcolors.ENDC}")
                    sys.stdout.flush()
                return cnames
            return False
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Domain {domain} does not exist{color.bcolors.ENDC}")
                sys.stdout.flush()
            return False
        except dns.resolver.Timeout:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}DNS query timed out for {domain}{color.bcolors.ENDC}")
                sys.stdout.flush()
            return False
        except Exception as e:
            if self.debug:
                self._print(f"{color.bcolors.FAIL}Error resolving {domain}: {e}{color.bcolors.ENDC}")
                sys.stdout.flush()
            return False

    def is_ip_in_range_subnet(self, ip, subnet):
        """Check if an IP address is in a given subnet.

        Args:
            ip (str): IP address to check
            subnet (str): Subnet in CIDR notation

        Returns:
            bool: True if the IP address is in the subnet, False otherwise
        """
        try:
            ip = ipaddress.ip_address(str(ip))
            network = ipaddress.ip_network(subnet, strict=False)
            return ip in network
        except ValueError as e:
            self._print(f"Error checking IP range: {e}")
            sys.stdout.flush()
            return False

    # ------------------------------------------------------------------
    # IP range loading
    # ------------------------------------------------------------------

    def read_aws_ip_ranges(self, url="https://ip-ranges.amazonaws.com/ip-ranges.json", folder="ip_ranges/aws.json"):
        """Read AWS S3 IP ranges from the live endpoint or fall back to the local file.

        Note: verify=False is intentional — the request is made to a raw IP address
        to avoid a circular DNS dependency, so TLS hostname verification cannot pass.

        Args:
            url (str): URL to read the IP ranges from
            folder (str): Path to the local fallback JSON file
        """
        data = None
        try:
            domain = url.split('/')[2]
            ip = self.resolver.resolve(domain, 'A')
            ip = ip[0].to_text()
            ip_url = f"http://{ip}/ip-ranges.json"
            headers = {"Host": domain}
            requests.packages.urllib3.disable_warnings()
            response = requests.get(ip_url, timeout=5, headers=headers, verify=False)
            data = response.json()
        except Exception:
            # Fall back to the bundled offline file
            try:
                if os.path.exists(folder):
                    with open(folder, "r") as f:
                        data = json.load(f)
                    self._print("Using offline AWS IP ranges (live fetch failed)")
                    sys.stdout.flush()
                else:
                    self._print(f"AWS IP ranges unavailable: {folder} not found")
                    sys.stdout.flush()
                    return []
            except Exception as e:
                self._print(f"Error reading {folder}: {e}")
                sys.stdout.flush()
                return []

        try:
            ipv4 = [p['ip_prefix'] for p in data.get('prefixes', []) if p.get('service') == 'S3']
            ipv6 = [p['ipv6_prefix'] for p in data.get('ipv6_prefixes', []) if p.get('service') == 'S3']
            ranges = ipv4 + ipv6
            if self.debug:
                self._print(f"{color.bcolors.OKGREEN}AWS IP ranges: {len(ipv4)} IPv4 + {len(ipv6)} IPv6 S3 ranges loaded{color.bcolors.ENDC}")
                sys.stdout.flush()
            return ranges
        except Exception as e:
            self._print(f"Error parsing AWS IP ranges: {e}")
            sys.stdout.flush()
            return []

    def read_azure_blob_ip_ranges(self, folder="ip_ranges/azure.json"):
        """Read Azure Blob Storage IP ranges from the given folder.

        Args:
            folder (str): Path to the Azure IP ranges JSON file
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
                self._print(f"{color.bcolors.OKGREEN}Azure IP ranges: {len(ip_ranges)} ranges loaded{color.bcolors.ENDC}")
                sys.stdout.flush()
            return ip_ranges
        except Exception as e:
            self._print(f"Error reading Azure IP ranges: {e}")
            sys.stdout.flush()
            return []

    # ------------------------------------------------------------------
    # Pattern loading
    # ------------------------------------------------------------------

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
                continue

            full_path = os.path.join(folder_path, filename)
            with open(full_path, "r") as f:
                data = yaml.safe_load(f)

            if filename.startswith("regex_"):
                for patterns in data.values():
                    regex_patterns.extend(patterns)
            else:
                for patterns in data.values():
                    hardcoded_patterns.extend(patterns)

        return regex_patterns, hardcoded_patterns


if __name__ == "__main__":
    debug = os.getenv("DEBUG", "false").lower() == "true"
    docker = os.getenv("DOCKER", "false").lower() == "true"

    aws_ip_ranges_var = os.getenv("AWS_IP_RANGES", "true").lower() == "true"
    azure_ip_ranges_var = os.getenv("AZURE_IP_RANGES", "true").lower() == "true"
    rate_limit_var = int(os.getenv("RATE_LIMIT", "100"))
    cache_size_var = int(os.getenv("CACHE_SIZE", "1000"))

    s3dns = S3DNS(
        debug=debug,
        aws_ip_ranges=aws_ip_ranges_var,
        azure_ip_ranges=azure_ip_ranges_var,
        rate_limit=rate_limit_var,
        cache_size=cache_size_var,
    )

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
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not ip_pattern.match(local_dns_server_ip):
        print(f"Invalid IP address format: {local_dns_server_ip}")
        sys.exit(1)

    # Get the real upstream DNS server address
    if not docker:
        dns_server = input(f"Enter real DNS server address (default: 1.1.1.1): ")
    else:
        dns_server = os.getenv('REAL_DNS_SERVER_IP', '1.1.1.1')

    if not dns_server:
        dns_server = '1.1.1.1'

    # Bucket file
    if not docker:
        bucket_file = input(f"Enter bucket file path (default: buckets.txt): ")
    else:
        bucket_file = os.getenv('BUCKET_FILE', 'buckets.txt')
    if not bucket_file:
        bucket_file = 'buckets.txt'

    s3dns.bucket_file = bucket_file

    dns_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not dns_pattern.match(dns_server):
        print(f"Invalid DNS server address format: {dns_server}")
        sys.exit(1)

    s3dns.real_dns = dns_server
    s3dns.resolver.nameservers = [dns_server]

    print(f"Using DNS server: {color.bcolors.color_text(s3dns.real_dns, color.bcolors.OKGREEN)}")

    # Bind UDP socket (with retry)
    sys.stdout.flush()
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((local_dns_server_ip, 53))
            break
        except Exception:
            print(f"Error binding UDP to {local_dns_server_ip}:53. Retrying...")
            time.sleep(5)

    # Bind TCP socket
    try:
        s3dns.start_tcp_server(local_dns_server_ip)
    except Exception as e:
        print(f"Warning: could not start TCP DNS server on port 53: {e}")

    print(f"Listening on {color.bcolors.color_text(local_dns_server_ip, color.bcolors.OKGREEN)}:53 (UDP + TCP)")
    print(f"{color.bcolors.OKBLUE}Running S3DNS Detector...\n{color.bcolors.ENDC}")
    sys.stdout.flush()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request_executor.submit(s3dns.handler, data, addr, sock)
            sys.stdout.flush()

        except KeyboardInterrupt:
            print("\nExiting...")
            sock.close()
            break
        except Exception as e:
            print(f"Error: {e}")
