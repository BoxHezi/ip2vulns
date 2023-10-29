# ip2vulns

An IP to vulnerabilities utility.
This tool is able to retrieve information related to given IP(s).
This tool takes advantage of [Shodan InternetDB API](https://internetdb.shodan.io/).

For CVE information, this tool retrieve CVE information from [NIST NVD](https://nvd.nist.gov/).

# Disclaimer

**By using this, you also agree to the term of use of the APIs used.**

- [NIST NVD - Term of Use](https://nvd.nist.gov/developers/terms-of-use)
- [Shodan InternetDB - Term of Services](https://static.shodan.io/legal/terms.html)

# Installation

Using the following pip command to install: `pip install ip2vulns`

# Usage

```text
usage: ip2vulns [-h] [-inet INTERNETDB [INTERNETDB ...]] [-o OUT] [-s CVSS] [-d] [--downloaddb] [--ho] [-v]

IP 2 vulneribility tools

options:
  -h, --help            show this help message and exit
  -inet INTERNETDB [INTERNETDB ...], --internetdb INTERNETDB [INTERNETDB ...]
                        Query information from https://internetdb.shodan.io/
                        support multiple ip and cidr, separate using space, e.g. -inet 8.8.8.8 51.83.59.99 192.168.0.0/24
                        if no database if specified, use ./databases/internetdb.db
  -o OUT, --out OUT     Define output file, default print to stdout
                        Available option: stdout (default), csv, json
                        Note: if -db flag is enabled, -out option will be disabled
  -s CVSS, --cvss CVSS  Enable cvss score filter, required a number
                        If 0 is given, targets found with no CVE information will be filtered out. And all CVEs will be checked.
                        When 0 is given, the process can be slow if huge amount of CVEs are founded. Not Recommend to pass 0 in.
  -d, --database        Write result to database
                        if no -o flag is provide, write data to internetdb.db in the same directory
  --downloaddb          download CAPEC and CWE database, csv file, store in ./databases directory
  --ho                  Output hostnames only for scan result.
                        This option DOES NOT apply to -d/--database option
  -v, --version         Print current version
```

### verbose SQL output
set environment variable `DEBUG` to True to enable SQL verbose output
In fish shell, use command `set -x DEBUG True` or in bash `export DEBUG=True`.

### NIST NVD Key
set environment variable `NVD_KEY` for lower delay of NIST NVD api. (Optional, but recommended)
[Request a key](https://nvd.nist.gov/developers/request-an-api-key)
