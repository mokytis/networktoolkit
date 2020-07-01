import re
import os
import click
import requests


def get_oui_db():
    """Gets the vendors of common mac address OUIs

    :return: dict[oui] = vendor
    :rtype: dict
    """
    url = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD"
    oui_db_path = "/tmp/oui_db"

    if not os.path.isfile(oui_db_path):
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(oui_db_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
    db = {}
    with open(oui_db_path) as f:
        content = f.read()
        for line in content.split("\n"):
            if line:
                if line[0] != "#":
                    if match := re.match(
                        r"^(([0-9A-F]{2}[:-]){2}([0-9A-F]{2}))\s(.+)$", line
                    ):
                        oui = match.group(1)
                        vendor = match.group(4)
                        db[oui] = vendor
    return db


def lookup_vendor(mac_address):
    """Find the vendor for a given mac address

    :param mac_address: Mac address to check the OUI of
    :type mac_address: str

    :return: Vendor of a given mac address
    :rtype: str
    """
    mac_address = mac_address.upper().replace("-", ":")
    if match := re.match(r"^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$", mac_address):
        db = get_oui_db()
        oui = mac_address[:8]
        vendor = db.get(oui, None)
        if vendor:
            if vendor.find("\t") != -1:
                long_name = vendor.split("\t")[1]
                return long_name
            else:
                return vendor
        else:
            return None
    else:
        click.echo("Invalid Mac Addr")
        return None


@click.command()
@click.argument("mac_address")
def cli(mac_address):
    vendor = lookup_vendor(mac_address)
    if vendor:
        click.echo(vendor)
