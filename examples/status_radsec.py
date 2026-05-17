import asyncio
import os

from loguru import logger

from pyrad2.dictionary import Dictionary
from pyrad2.radsec.client import RadSecClient

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 2083

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
CA_CERTFILE = os.path.join(THIS_FOLDER, "certs/ca/ca.cert.pem")
CLIENT_CERTFILE = os.path.join(THIS_FOLDER, "certs/client/client.cert.pem")
CLIENT_KEYFILE = os.path.join(THIS_FOLDER, "certs/client/client.key.pem")


def format_attribute_values(values):
    """Return RADIUS attribute values in a readable form for the example."""
    return [value.hex() if isinstance(value, bytes) else value for value in values]


async def main():
    async with RadSecClient(
        server=SERVER_HOST,
        port=SERVER_PORT,
        secret=b"radsec",
        dict=Dictionary(THIS_FOLDER + "/dictionary"),
        certfile=CLIENT_CERTFILE,
        keyfile=CLIENT_KEYFILE,
        certfile_server=CA_CERTFILE,
    ) as client:
        request = client.create_status_packet()

        logger.info("Sending RadSec Status-Server request")
        reply = await client.send_packet(request)

    if reply is None:
        logger.error("RadSec server does not reply")
        return

    logger.info("Attributes returned by server:")
    for attr in reply.keys():
        logger.info("{}: {}", attr, format_attribute_values(reply[attr]))


if __name__ == "__main__":
    asyncio.run(main())
