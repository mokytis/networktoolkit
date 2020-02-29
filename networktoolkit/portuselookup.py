import os
import click
import requests


def get_port_use_db():
    """Gets the services that commonly run on certain ports

    :return: dict[port] = service
    :rtype: dict
    """
    url = "http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    db_path = "/tmp/port_db"

    if not os.path.isfile(db_path):
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(db_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
    db = {}
    with open(db_path) as f:
        content = f.read()
        for line in content.split("\n")[1:]:
            if line:
                parts = line.split(",")
                if len(parts) >= 4:
                    service = parts[0]
                    port = parts[1]
                    if service:
                        db[port] = service
    return db


def lookup_port_use(port):
    """Find a service that commonly runs on a given port

    :param port: Port to check
    :type port: int

    :return: Service that commonly runs on the given port
    :rtype: str
    """
    db = get_port_use_db()
    service = db.get(f"{port}", None)
    return service


@click.command()
@click.argument("port", type=int)
def cli(port):
    port_use = lookup_port_use(port)
    if port_use:
        click.echo(port_use)
