from setuptools import setup, find_packages
from ip2vulns.version import __version__

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
    version=__version__,
    packages=find_packages(),
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
