from . import version
from .Services import InternetDBService

from .Utils import PipeUtils
from .Utils import ArgUtils


def main():
    args = ArgUtils.init_argparse().parse_args()  # init argparse

    if PipeUtils.has_pipe_data():  # read from pipe, enable internetdb by default
        args.input = PipeUtils.read_from_pipe()
    elif not any(vars(args).values()):  # check if argument is provided, if not, print help
        args = ArgUtils.init_argparse().parse_args(["-h"])

    if args.input:  # type(input) => list
        InternetDBService.start(args.input, args.out, args.cvss, args.nostdout)
    elif args.version:
        print(version.__version__)


if __name__ == "__main__":
    main()
