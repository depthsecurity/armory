from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the Readme
with open(path.join(here, "Readme.md"), encoding="UTF-8") as f:
    long_description = f.read()


setup(
    name="depth-armory",
    version="1.0.0",
    description=(
        "Armory is a tool meant to take in a lot of external and discovery "
        "data from a lot of tools, add it to a database and correlate all of"
        " related information."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/depthsecurity/armory",
    author="Depth Security",
    author_email="info@depthsecurity.com",
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 5 - Production/Stable",
        # Indicate who your project is intended for
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
    # Keywords that the project relates to.
    keywords="pentesting security",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    install_requires=[
        "configparser",
        "sqlalchemy",
        "sqlalchemy_mixins",
        "tld",
        "dnspython",
        "netaddr",
        "pyperclip",
        "requests",
        "ipwhois",
        "whois",
        "fuzzywuzzy[speedup]",
        "xmltodict",
        "bs4",
        "thready",
        "argcomplete",
        "tldextract",
        "subprocess32; python_version < '3.3'",
        "ipaddr",
        "mysqlclient",
        "lxml",
        "IPython > 5.0,< 6.0; python_version < '3.1'",
        "IPython; python_version > '3.1'",
    ],
    test_suite="nose.collector",
    tests_require=["nose"],
    # Additional groups of dependencies.
    # You can install these with the following syntax:
    # $ pip install -e .[dev,test]
    extras_require={
        "dev": ["check-manifest", "tox"],
        "test": ["coverage", "mock; python_version < '3.4'"],
    },
    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        "console_scripts": [
            "armory=armory.armory:main",
            "armory-shell=armory.shell:main",
        ]
    },
)
