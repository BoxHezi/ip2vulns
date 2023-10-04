import argparse

from pprint import pprint

from . import utils
from .Services import InternetDBService, CVEService


def init_argparse():
    arg = argparse.ArgumentParser(description="IP 2 vulneribility tools", formatter_class=argparse.RawTextHelpFormatter)
    # arg.add_argument("-t6",
    #                  help="Enable CIDR to IP for ipv6 addresses, disabled by default",
    #                  action="store_true", default=False)
    # arg.add_argument("-i", "--ip", help="Query ip information, using API from ipapi.is\n"
    #                                     "support multiple ip, separate using space, e.g. -i 8.8.8.8 51.83.59.99",
    #                  nargs="+")
    # arg.add_argument("-a", "--asn", help="Query ASN information, using API from ipapi.is\n"
    #                                  "provide ASN without the prefix 'as'\n"
    #                                  "support multiple ASN query, separate using space, e.g. -a 23500 23501 23501",
    #                  nargs="+")
    arg.add_argument("-inet", "--internetdb", help="Query information from https://internetdb.shodan.io/\n"
                                                   "support multiple ip and cidr, separate using space, "
                                                   ":e.g. -inet 8.8.8.8 51.83.59.99 192.168.0.0/24\n"
                                                   "if no database if specified, use ./databases/internetdb.db",
                     nargs="+")
    # arg.add_argument("-cve", "--cve", help="get cve information from database\n"
    #                                        "require to use -db for specifying a database",
    #                  action="store_true")
    arg.add_argument("-db", "--database", help="Specify database will be used to store/retrieve data")
    arg.add_argument("--downloaddb", help="download CAPEC and CWE database, csv file, store in ./databases directory",
                     action="store_true")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout")
    return arg


def main():
    args = init_argparse().parse_args()  # init argparse

    # if args.ip:
    #     for i in args.ip:
    #         pprint(utils.resp_2_json(utils.ip_query(str(i))))
    #
    # if args.asn:
    #     for a in args.asn:
    #         pprint(utils.resp_2_json(utils.asn_query(str(a))))

    if args.internetdb:  # type(internetdb) => list
        db_path = args.database if args.database else "./databases/internetdb.db"
        if args.database:
            InternetDBService.start_db_enabled(args.internetdb, db_path)
        else:
            InternetDBService.start(args.internetdb, args.out)
        # for item in succeed:
        #     print(str(item))
        #
        # for item in failed:
        #     print(item)

    if args.downloaddb:
        CVEService.download_local_db()

    # if args.cve:
    #     if not args.database:
    #         raise "Database required"
    #     db_path = args.database
    #     targets = CVEService.start(db_path)
    #     pprint(targets)


if __name__ == "__main__":
    main()
