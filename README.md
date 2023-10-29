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
  -d, --database        Write result to database, using SQLite3 database
                        if no -o flag is provide, write data to internetdb.db in the same directory
  --downloaddb          download CAPEC and CWE database, csv file, store in ./databases directory
  --ho                  Output hostnames only for scan result.
                        This option DOES NOT apply to -d/--database option
  -v, --version         Print current version
```

# Features

The scan operation will be splitted into several groups. Each group contains maximum 256 IPs.

## Output to file

When no `-o/--out` option is provided, results are printed to stdout.

When providing the `-o/--out` option, results will be written to files.
Each group's result will be written to separated files. Group index (starting from 0) will be appened to file output filename.

> If 512 IPs are scanned. Results will be written to 2 files.
> If `-o test.csv` is given, then the output files will be:
>
> - test_0.csv
> - test_1.csv

# Local CVE Database

The project use a local CVE database in order to avoid querying duplicated CVE from NIST NVD.

The local database use [TinyDB](https://github.com/msiemens/tinydb).
The local database will be stored in `$HOME/.config/ip2vulns/cve_db.json`

> **NOTE: This database is not related to `-d/--database` option.**

### Verbose SQL output

set environment variable `DEBUG` to True to enable SQL verbose output
In fish shell, use command `set -x DEBUG True` or in bash `export DEBUG=True`.

### NIST NVD Key

set environment variable `NVD_KEY` for lower delay of NIST NVD api. (Optional, but recommended)
[Request a key](https://nvd.nist.gov/developers/request-an-api-key)
