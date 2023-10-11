import argparse

from . import utils
from .Services import InternetDBService, CVEService


def init_argparse():
    arg = argparse.ArgumentParser(description="IP 2 vulneribility tools", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("-inet", "--internetdb", help="Query information from https://internetdb.shodan.io/\n"
                                                   "support multiple ip and cidr, separate using space, "
                                                   ":e.g. -inet 8.8.8.8 51.83.59.99 192.168.0.0/24\n"
                                                   "if no database if specified, use ./databases/internetdb.db",
                     nargs="+")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout\n"
                                         "Available option: stdout (default), csv, json\n"
                                         "Note: if -db flag is enabled, -out option will be disabled")
    arg.add_argument("-s", "--cvss", help="enable cvss score filter, required a number\n"
                                           "")
    arg.add_argument("-db", "--database", help="Write result to database\n"
                                               "if no -o flag is provide, write data to internetdb.db in the same directory",
                    action="store_true")
    arg.add_argument("--downloaddb", help="download CAPEC and CWE database, csv file, store in ./databases directory",
                     action="store_true")
    return arg


def main():
    args = init_argparse().parse_args()  # init argparse
    if utils.has_pipe_data():  # read from pipe, enable internetdb by default
        args.internetdb = utils.read_from_pipe()

    if args.internetdb:  # type(internetdb) => list
        InternetDBService.start(args.internetdb, args.out, args.database, args.cvss)

    if args.downloaddb:
        CVEService.download_local_db()


if __name__ == "__main__":
    main()
