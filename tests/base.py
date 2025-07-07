import os
from contextlib import contextmanager

from loguru import logger

from pyrad2.server_async import (
    ServerAsync,
)

TEST_ROOT_PATH = os.path.dirname(os.path.realpath(__file__))


@contextmanager
def capture_logs(level="INFO", format="{level}:{name}:{message}"):
    """Capture loguru-based logs."""
    output = []
    handler_id = logger.add(output.append, level=level, format=format)
    yield output
    logger.remove(handler_id)


class DummyServer(ServerAsync):
    def handle_auth_packet(self, protocol, pkt, addr):
        self.auth_called = True

    def handle_acct_packet(self, protocol, pkt, addr):
        self.acct_called = True

    def handle_coa_packet(self, protocol, pkt, addr):
        self.coa_called = True

    def handle_disconnect_packet(self, protocol, pkt, addr):
        self.disconnect_called = True
