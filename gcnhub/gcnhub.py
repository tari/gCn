#!/usr/bin/python

# globalCALCnet IRC Bridge: logging.py
# Christopher Mitchell, 2011-2014
# Licensed under the BSD 3-Clause License (see LICENSE)

# Port to run TCP server on
GCNPORT = 4295
# Port to run SSL server on. CERTFILE and KEYFILE must also be specified.
SSLPORT = 4296
# Path to SSL certificate file
CERTFILE = None
# Path to SSL key file
KEYFILE = None

from collections import defaultdict
import struct
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint, SSL4ServerEndpoint
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import ServerFactory
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from logging import *


class GCNProtocol(Protocol):
    def __init__(self):
        self.buffer = bytearray()

        self.hub_name = None
        self.local_name = None
        self.calculators = []

    def payload_len(self):
        assert len(self.buffer) >= 2
        return self.buffer[0] | (self.buffer[1] << 8)

    def have_message(self):
        if len(self.buffer) >= 3:
            return len(self.buffer) >= self.payload_len() + 3
        else:
            return False

    def dataReceived(self, data):
        # Message format:
        # 2 bytes little-endian, length of payload
        # 1 byte, msgtype
        # <length> bytes, payload
        self.factory.stats.add_received(len(data))
        self.buffer.extend(data)

        while self.have_message():
            msg_type = chr(self.buffer[2])
            payload = self.buffer[3:3 + self.payload_len()]
            self.handle_msg(msg_type, payload)
            del self.buffer[:3 + self.payload_len()]

    def connectionLost(self, reason):
        if self.hub_name:
            endpoints = self.factory.virtual_hubs[self.hub_name]
            endpoints.remove(self)
            if len(endpoints) is 0:
                log_info('gcnhub: [MSG] Virtual hub ' + self.hub_name + ' lost its last endpoint and was destroyed')
                del self.factory.virtual_hubs[self.hub_name]
        self.factory.stats.remove_calculators(len(self.calculators))

    @property
    def addrport(self):
        """Hack to avoid needing to change a lot of the original code."""
        return str(self.transport.getPeer())

    def endpoints(self):
        """Generator over all endpoints on the current vhub, excluding self."""
        assert self.hub_name is not None
        for endpoint in self.factory.virtual_hubs[self.hub_name]:
            if endpoint is not self:
                yield endpoint

    def handle_msg(self, msg_type, payload):
        if len(payload) > 300:
            log_warn("gcnhub: [MSG] Rejecting message of length " + str(len(payload)))
            return

        if msg_type == 'j':
            self.handle_vhub_join(payload)
        elif msg_type == 'c':
            self.handle_vhub_calc(payload)
        elif msg_type == 'b':
            self.handle_broadcast(payload)
        elif msg_type == 'f':
            self.handle_frame(payload)
        else:
            log_warn("gcnhub: [MSG] Unknown message of length " + str(len(payload)) + "")

    def handle_vhub_join(self, payload):
        """Handles incoming "join vhub" messages.

        Associates this endpoint with a virtual hub, setting local_name and hub_name on self if join is accepted.
        """
        hub_name_len = payload[0]
        hub_name = str(payload[1:1 + hub_name_len])

        local_name_idx = hub_name_len + 2
        local_name_len = payload[local_name_idx - 1]
        local_name = payload[local_name_idx:local_name_idx + local_name_len]

        if 0 < len(local_name) < 16 and 0 < len(hub_name) < 16:
            log_info("gcnhub: [MSG] Join from " + self.addrport + ": " + local_name + "->" + hub_name)
            self.local_name = local_name
            self.hub_name = hub_name
            self.factory.virtual_hubs[hub_name].append(self)
        else:
            log_warn("gcnhub: [MSG] INVALID join from " + self.addrport + ": " + local_name + "->" + hub_name)

    def handle_vhub_calc(self, payload):
        """Handles incoming "new calculator" messages."""
        if len(payload) != 10:
                log_warn("gcnhub: [MSG] " + self.addrport + " got a calc add with invalid length")
        elif self.hub_name is None:
                log_warn("gcnhub: [MSG] " + self.addrport + " tried to add calculator " +
                         payload + " but is not joined to a hub")
        else:
            log_info("gcnhub: [MSG] " + self.addrport + " is adding calculator " + payload + "...")
            sid = payload
            if sid not in self.calculators:
                self.factory.stats.add_calculator()
                self.calculators.append(sid)

    def transmit(self, data):
        """Transmits a frame."""
        self.factory.stats.add_transmitted(len(data))
        self.transport.write(data)

    @classmethod
    def pack_message(cls, ident, payload):
        msg = bytearray(3 + len(payload))
        struct.pack_into('<hc', msg, 0, len(payload), ident)
        msg[3:] = payload
        return msg

    @classmethod
    def pack_broadcast(cls, payload):
        return cls.pack_message('b', payload)

    def handle_broadcast(self, payload):
        """Handles incoming broadcast frames."""
        if self.hub_name is None:
            log_warn("gcnhub: [MSG] " + self.addrport + " tried to send a broadcast, but is not joined to a hub")
        elif len(payload) > 256 + 5 + 5 + 2 + 3:
            log_warn("gcnhub: [MSG] " + self.addrport + " sent an overflow-length broadcast")
        else:
            message = self.pack_broadcast(payload)
            for endpoint in self.endpoints():
                endpoint.transmit(message)

    @classmethod
    def pack_directed(cls, payload):
        return cls.pack_message('f', payload)

    def handle_frame(self, payload):
        """Handles incoming directed frames."""
        if self.hub_name is None:
            log_warn("gcnhub: [MSG] " + self.addrport + " tried to send a frame, but is not joined to a hub")
        elif len(payload) > 256 + 5 + 5 + 2 + 3:
            log_warn("gcnhub: [MSG] " + self.addrport + " sent an overflow-length frame")
        else:
            # "new calculator" messages have the calculator address as a hex string (10 characters) rather than 5-byte
            # binary address. Do this transformation to work around it in a stupid fashion.
            dest_addr = ''.join('{:02X}'.format(b) for b in payload[2:7])
            # Find the endpoint that has this calculator, if any (not including this one, because if the calculator is
            # on this endpoint we don't need to do anything).
            for endpoint in self.endpoints():
                if dest_addr in endpoint.calculators:
                    endpoint.transmit(self.pack_directed(payload))
                    break


class GCNFactory(ServerFactory):
    protocol = GCNProtocol

    def __init__(self, stats):
        self.stats = stats
        self.virtual_hubs = defaultdict(list)


class StatisticsTracker(object):
    def __init__(self):
        self.bytes_transmitted = self.bytes_received = 0
        self.calcs_active = self.max_calcs = 0

    def add_received(self, n):
        self.bytes_received += n

    def add_transmitted(self, n):
        self.bytes_transmitted += n

    def add_calculator(self):
        self.calcs_active += 1
        self.max_calcs = max(self.calcs_active, self.max_calcs)

    def remove_calculators(self, n):
        self.calcs_active -= n


if __name__ == '__main__':
    try:
        stats = StatisticsTracker()
        factory = GCNFactory(stats)

        ep = TCP4ServerEndpoint(reactor, GCNPORT)
        ep.listen(factory)

        if KEYFILE and CERTFILE:
            ep_ssl = SSL4ServerEndpoint(reactor, SSLPORT, DefaultOpenSSLContextFactory(KEYFILE, CERTFILE))
            ep_ssl.listen(factory)
        else:
            log_warn('Key and certificate not specified; not running SSL server.')

        reactor.run()
    except KeyboardInterrupt:
        log_error('gcnhub: You pressed Ctrl+C!')
