import argparse

from . import version
from .Services import InternetDBService

from .Utils import PipeUtils


def init_argparse():
    arg = argparse.ArgumentParser(description="IP 2 vulnerability tools", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("-i", "--input", help="Query information from https://internetdb.shodan.io/\n"
                                                   "support multiple ip and cidr, separate using space, "
                                                   "e.g. -i 8.8.8.8 51.83.59.99 192.168.0.0/24\n",
                     nargs="+")
    arg.add_argument("-s", "--cvss", help="Enable cvss score filter, required a number\n"
                                        "If 0 is given, targets found with no CVE information will be filtered out. And all CVEs will be checked.\n"
                                        "When 0 is given, the process can be slow if huge amount of CVEs are founded. Not Recommend to pass 0 in.")
    arg.add_argument("-o", "--out", help="Define output file, default print to stdout\n"
                                         "Available option: stdout (default), csv, json\n"
                                         "For csv: please specify filename\n"
                                         "For json: a directory out_json will be created")
    arg.add_argument("--disable-stdout", help="Disable stdout", action="store_true")
    arg.add_argument("-v", "--version", help="Print current version", action="store_true")
    return arg


def parse_args_input(input: list):
    if len(input) == 1:  # when input is possibly a file
        try:
            with open(input[0]) as f:  # input is a file
                # print("input is a file")
                result = [line.strip() for line in f]
                return result
        except FileNotFoundError:  # input is ip or cidr
            pass
    # print("input is IP or CIDR")
    return input


def main():
    args = init_argparse().parse_args()  # init argparse

    if PipeUtils.has_pipe_data():  # read from pipe, enable internetdb by default
        args.input = PipeUtils.read_from_pipe()
    elif not any(vars(args).values()):  # check if argument is provided, if not, print help
        args = init_argparse().parse_args(["-h"])

    if args.input:  # type(input) => list
        input_list = parse_args_input(args.input)
        InternetDBService.start(input_list, args.out, args.cvss, args.disable_stdout)
    elif args.version:
        print(version.__version__)


if __name__ == "__main__":
    main()
