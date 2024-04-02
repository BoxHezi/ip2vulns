# ip2vulns

An IP to vulnerabilities utility.
This tool is able to retrieve information related to given IP(s).
This tool takes advantage of [Shodan InternetDB API](https://internetdb.shodan.io/).

For CVE information, this tool retrieve CVE information from a github repo [nvd-json-data-feed](https://github.com/fkie-cad/nvd-json-data-feeds/)

# Disclaimer

**By using this, you also agree to the term of use of the APIs used.**

- [Shodan InternetDB - Term of Services](https://static.shodan.io/legal/terms.html)

# Installation

## Install with `pip`

Using the following pip command to install: `pip install ip2vulns`

# Usage

```text
usage: ip2vulns [-h] [-i INPUT [INPUT ...]] [-s CVSS] [-o OUT] [--disable-stdout] [-v]

IP 2 vulnerability tools

options:
  -h, --help            show this help message and exit
  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        Query information from https://internetdb.shodan.io/
                        support multiple ip and cidr, separate using space, e.g. -i 8.8.8.8 51.83.59.99 192.168.0.0/24
  -s CVSS, --cvss CVSS  Enable cvss score filter, required a number
                        If 0 is given, targets found with no CVE information will be filtered out. And all CVEs will be checked.
                        When 0 is given, the process can be slow if huge amount of CVEs are founded. Not Recommend to pass 0 in.
  -o OUT, --out OUT     Define output file, default print to stdout
                        Available option: stdout (default), csv, json
                        For csv: please specify filename
                        For json: a directory out_json will be created
  --disable-stdout      Disable stdout
  -v, --version         Print current version
```

## Output to file

When output to csv file, please specify the filename.
For example, `ip2vulns -i 1.1.1.1 -o 1.1.1.1.csv`, the output file will be `1.1.1.1.csv`.

When output to json file, a directory `out_json` will be created. Results will be stored using `<ip>.json`.
For example, `ip2vulns -i 1.1.1.1 -o json`, then a directory `out_json` will be created. And the output filename will be `1.1.1.1.json`.

To disable print to stdout, apply `--disable-stdout` in command line argument

## Example

- `ip2vulns -i <ip address> <cidr>`
- `ip2vulns -i <ip address> <cidr> -s 7`
- `echo "<ip address>" | ip2vulns`
- `echo "<ip address>" | ip2vulns -s 7`

## Use `ip2vulns` in Python script

```python
from ip2vulns import ip2vulns_scan

# s => success list
# f => failure list
s, f = ip2vulns_scan("[<ip address>]")  # ip address need to be passed in as a LIST
```
