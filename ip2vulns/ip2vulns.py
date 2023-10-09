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
    arg.add_argument("-s", "--cvss", help="enable cvss score filter, required a number\n"
                                           "")
    arg.add_argument("-db", "--database", help="Specify database will be used to store/retrieve data")
    arg.add_argument("--downloaddb", help="download CAPEC and CWE database, csv file, store in ./databases directory",
                     action="store_true")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout\n"
                                         "Available option: stdout (default), csv, json\n"
                                         "Note: if -db flag is enabled, -out option will be disabled")
    return arg


def main():
    args = init_argparse().parse_args()  # init argparse
    if utils.has_pipe_data():  # read from pipe, enable internetdb by default
        args.internetdb = utils.read_from_pipe()

    if args.internetdb:  # type(internetdb) => list
        db_path = args.database if args.database else "./databases/internetdb.db"
        if args.database:
            InternetDBService.start_db_enabled(args.internetdb, db_path, args.cvss)
        else:
            InternetDBService.start(args.internetdb, args.out, args.cvss)

    if args.downloaddb:
        CVEService.download_local_db()


if __name__ == "__main__":
    main()
