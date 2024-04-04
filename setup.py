from setuptools import setup, find_packages


VERSION_FILE_PATH = "./src/ip2vulns/version.py"
README_PATH = "./README.md"


def get_version():
    with open(VERSION_FILE_PATH) as f:
        for line in f:
            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]


def get_long_description():
    with open(README_PATH, "r") as file:
        return file.read()


__version = get_version()
__long_desc = get_long_description()
__requires = [
    "requests",
    "tqdm"
]
__entry = {
    "console_scripts": [
        "ip2vulns = ip2vulns.ip2vulns:main"
    ]
}

setup(
    name="ip2vulns",
    version=__version,
    package_dir={"": "src"},
    packages=find_packages("src"),
    author="Box Hezi",
    author_email="hezipypi.yixdpu@bumpmail.io",
    description="An IP to vulnerability utility",
    long_description=__long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/BoxHezi/ip2vulns",
    install_requires=__requires,
    entry_points=__entry,
    python_requires=">=3.8"
)
