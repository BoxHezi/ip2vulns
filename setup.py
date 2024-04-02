from setuptools import setup, find_packages


VERSION_FILE_PATH = "./src/ip2vulns/version.py"


def get_version():
    with open(VERSION_FILE_PATH) as f:
        for line in f:
            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]
__version = get_version()


long_desc = ""
with open("./README.md", "r") as file:
    for line in file:
        long_desc += line


requires = [
    "requests",
    "tqdm"
]

setup(
    name="ip2vulns",
    version=__version,
    package_dir={"": "src"},
    packages=find_packages("src"),
    author="Box Hezi",
    author_email="hezipypi.yixdpu@bumpmail.io",
    description="An IP to vulnerability utility",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://github.com/BoxHezi/ip2vulns",
    install_requires=requires,
    entry_points={
        'console_scripts': [
            'ip2vulns = ip2vulns.ip2vulns:main'
        ]
    },
    python_requires=">=3.8"
)
