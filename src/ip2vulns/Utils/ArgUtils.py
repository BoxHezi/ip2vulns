import argparse


def init_argparse():
    arg = argparse.ArgumentParser(description="IP 2 vulnerability tools", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("-i", "--input", help="Query information from https://internetdb.shodan.io/\n"
                                           "support multiple ip and cidr, separate using space, "
                                           "e.g. -i 8.8.8.8 51.83.59.99 192.168.0.0/24\n",
                     nargs="+")
    arg.add_argument("--cvedict", help="Config CVE database"
                                       "integrate with go-cvedict, checkout at: https://github.com/BoxHezi/go-cvedict",
                     default=None)
    arg.add_argument("-s", "--cvss", help="Enable cvss score filter, required a number\n"
                                          "If 0 is given, targets found with no CVE information will be filtered out. "
                                          "And all CVEs will be checked.\n"
                                          "When 0 is given, the process can be slow if huge amount of CVEs are founded."
                                          "Not Recommend to pass 0 in.")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout\n"
                                         "Available option: stdout (default), csv, json\n"
                                         "For csv: please specify filename\n"
                                         "For json: a directory out_json will be created")
    arg.add_argument("--nostdout", help="Disable print result to stdout\n"
                                        "IP with unsuccessful querying (i.e. Exception happened) will still be printed",
                     action="store_true")
    arg.add_argument("-v", "--version", help="Print current version", action="store_true")
    return arg
