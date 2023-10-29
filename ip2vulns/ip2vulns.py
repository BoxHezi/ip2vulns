import argparse

from . import version
from . import utils
from .Services import InternetDBService, CVEService


def init_argparse():
    arg = argparse.ArgumentParser(description="IP 2 vulneribility tools", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("-inet", "--internetdb", help="Query information from https://internetdb.shodan.io/\n"
                                                   "support multiple ip and cidr, separate using space, "
                                                   "e.g. -inet 8.8.8.8 51.83.59.99 192.168.0.0/24\n"
                                                   "if no database if specified, use ./databases/internetdb.db",
                     nargs="+")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout\n"
                                         "Available option: stdout (default), csv, json\n"
                                         "Note: if -db flag is enabled, -out option will be disabled")
    arg.add_argument("-s", "--cvss", help="Enable cvss score filter, required a number\n"
                                          "If 0 is given, targets found with no CVE information will be filtered out. And all CVEs will be checked.\n"
                                          "When 0 is given, the process can be slow if huge amount of CVEs are founded. Not Recommend to pass 0 in.")
    arg.add_argument("-d", "--database", help="Write result to database, using SQLite3 database\n"
                                               "if no -o flag is provide, write data to internetdb.db in the same directory",
                    action="store_true")
    arg.add_argument("--downloaddb", help="download CAPEC and CWE database, csv file, store in ./databases directory",
                     action="store_true")
    arg.add_argument("--ho", help="Output hostnames only for scan result.\n"
                     "This option DOES NOT apply to -d/--database option", action="store_true")
    arg.add_argument("-v", "--version", help="Print current version", action="store_true")
    return arg


def main():
    args = init_argparse().parse_args()  # init argparse
    if utils.has_pipe_data():  # read from pipe, enable internetdb by default
        args.internetdb = utils.read_from_pipe()

    if args.internetdb:  # type(internetdb) => list
        InternetDBService.start(args.internetdb, args.out, args.database, args.cvss, args.ho)

    if args.downloaddb:  # download CAPEC and CWE database
        CVEService.download_local_db()

    if args.version:
        print(version.__version__)


if __name__ == "__main__":
    main()
