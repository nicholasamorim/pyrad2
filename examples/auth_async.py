#!/usr/bin/python

import asyncio
import traceback

from loguru import logger

from pyrad2.client_async import ClientAsync
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType


def get_async_client():
    return ClientAsync(
        server="localhost",
        secret=b"Kah3choteereethiejeimaeziecumi",
        timeout=4,
        dict=Dictionary("dictionary"),
    )


def create_request(client, user):
    req = client.CreateAuthPacket(User_Name=user)

    req["NAS-IP-Address"] = "192.168.1.10"
    req["NAS-Port"] = 0
    req["Service-Type"] = "Login-User"
    req["NAS-Identifier"] = "trillian"
    req["Called-Station-Id"] = "00-04-5F-00-0F-D1"
    req["Calling-Station-Id"] = "00-01-24-80-B3-9C"
    req["Framed-IP-Address"] = "10.0.0.100"

    return req


def log_reply(reply):
    if reply.code == PacketType.AccessAccept:
        logger.info("Access accepted")
    else:
        logger.error("Access denied")

    logger.info("Attributes returned by server:")
    for i in reply.keys():
        logger.info("{}: {}", i, reply[i])


async def test_auth1():
    client = None
    try:
        client = get_async_client()

        await client.initialize_transports(
            enable_auth=True,
            local_addr="127.0.0.1",
            local_auth_port=8000,
            enable_acct=True,
            enable_coa=True,
        )

        req = create_request(client, "wichert")
        reply = await client.SendPacket(req)

        try:
            if reply.code == PacketType.AccessAccept:
                logger.info("Access accepted")
            else:
                logger.error("Access denied")

            logger.info("Attributes returned by server:")
            for key in reply.keys():
                logger.info("{}: {}", key, reply[key])

        except Exception as packet_exc:
            logger.error("EXCEPTION: {}", packet_exc)

        await client.deinitialize_transports()
        logger.info("END")

    except Exception as exc:
        logger.error("Error: {}", exc)
        logger.error("\n".join(traceback.format_exc().splitlines()))

        if client is not None:
            await client.deinitialize_transports()


async def test_multi_auth():
    client = None
    try:
        client = get_async_client()

        await client.initialize_transports(
            enable_auth=True,
            local_addr="127.0.0.1",
            local_auth_port=8000,
            enable_acct=True,
            enable_coa=True,
        )

        tasks = []
        for i in range(255):
            req = create_request(client, f"user{i}")
            task = client.SendPacket(req)  # assuming SendPacket is awaitable
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for response in responses:
            if isinstance(response, Exception):
                logger.error("EXCEPTION: %s", response)
            else:
                log_reply(response)

    except Exception as exc:
        logger.error("Unhandled Error: {}", exc)
        logger.error("\n".join(traceback.format_exc().splitlines()))

    finally:
        if client:
            await client.deinitialize_transports()
            logger.info("END")


if __name__ == "__main__":
    asyncio.run(test_auth1())
    asyncio.run(test_multi_auth())
