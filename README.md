# Network Toolkit

A collection of networking tools


## Installation

You can install networktookit from pypi.
This requires you to have python3.8 installed.

```bash
python -m pip install --upgrade networktoolkit
```

## Usage

The project contain many tools.

The current tools are:

* `vendorlookup` - check the vendor of a macaddress
* `portuselookup` - checks to see if a given port is allocated to any particular service
* `networkscan` - allows you to scan a given ip range and returns a list of all ips (with mac addresses and vendors) in the given range that are accessable on the network
* `arpspoof` - allows you to spoof a given ip address by sending ARP responses

Each of these has its own help page.
As an example, you can assess the help for `arpspoof` like this:

```bash
arpspoof --help
```


## About

This project uses [scapy](https://scapy.net/) for generating and sending network packets, and [click](https://click.palletsprojects.com) to give each python script a command line interface.

## Contributing

Feel free to contribute to this project by opening a merge request.
I would request that all contributed code is pep8 complient.

## Issues

If anything is broke, you have a usage question, or a feature suggestion feel free to create an issue on gitlab.


