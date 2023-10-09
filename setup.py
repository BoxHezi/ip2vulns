from setuptools import setup, find_packages

setup(
    name="ip2vulns",
    version="0.5.1",
    packages=find_packages(),
    author="Box Hezi",
    author_email="hezipypi.yixdpu@bumpmail.io",
    description="An IP to vulnerability utility",
    install_requires=[],
    entry_points={
        'console_scripts': [
            'ip2vulns = ip2vulns.ip2vulns:main'
        ]
    }
)
