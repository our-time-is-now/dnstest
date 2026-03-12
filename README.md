```
usage: dnstest.py [-h] -d DOMAIN -l LIST [-k PUBKEY] [-w WORKERS] [-m {full,edns,resolve-only,tunnel-only}]
                  [-r ROUND] [-p PORT_RANGE] [-o OUTPUT] [--no-clear]

DNS tunnel testing tool with multiple scan methods

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Domain name for DNS resolution (e.g., example.com)
  -l, --list LIST       Path to file containing DNS resolver IPs (one per line)
  -k, --pubkey PUBKEY   Path to public key file for dnstt (default: pub.pem)
  -w, --workers WORKERS
                        Number of concurrent workers (default: 10)
  -m, --method {full,edns,resolve-only,tunnel-only}
                        Scan method: full : Complete test (DNS resolution + EDNS + tunnel) edns : DNS
                        resolution + EDNS test only (no tunnel) resolve-only : DNS resolution test only
                        tunnel-only : Tunnel test only (skip DNS resolution check)
  -r, --round ROUND     How many time tunnel test runs for every resolver higher is better but recommanded is 3 (default:1)
  -p, --port-range PORT_RANGE
                        Port range for tunnel clients (format: START-END, default: 2083-2100)
  -o, --output OUTPUT   Output file for successful resolvers (default: successful_resolvers.txt)
  --no-clear            Disable screen clearing between tests

Examples:
  dnstest.py -d example.com -l dns_list.txt -m full
  dnstest.py -d example.com -l dns_list.txt -m edns -w 20
  dnstest.py -d example.com -l dns_list.txt -m resolve-only -k custom.pem
  dnstest.py -d example.com -l dns_list.txt -m tunnel-only -p 2083-2200
  dnstest.py -d example.com -l dns_list.txt -m tunnel-only -p 2083-2200 -r 2

```
