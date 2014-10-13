import struct
from twisted.trial import unittest
from twisted.test import proto_helpers

import gcnhub


class MetaHubTestCase(unittest.TestCase):
    def setUp(self):
        self.stats = gcnhub.StatisticsTracker()
        self.factory = gcnhub.GCNFactory(self.stats)

        self.proto1 = self.factory.buildProtocol(('127.0.0.1', 0))
        self.tr1 = proto_helpers.StringTransportWithDisconnection()
        self.tr1.protocol = self.proto1
        self.proto1.makeConnection(self.tr1)

        self.proto2 = self.factory.buildProtocol(('127.0.0.1', 1))
        self.tr2 = proto_helpers.StringTransport()
        self.proto2.makeConnection(self.tr2)

    def _make_pstr(self, s):
        b = bytearray(len(s) + 1)
        b[0] = len(s)
        b[1:] = s
        return b

    def _send(self, proto, mtype, payload):
        proto.dataReceived(struct.pack('<hc', len(payload), mtype) + payload)

    def _join_hub(self, proto, hub, name):
        self._send(proto, 'j', self._make_pstr(hub) + self._make_pstr(name))

    def _join_calc(self, proto, sid):
        self._send(proto, 'c', sid)

    def test_hub_join(self):
        self._join_hub(self.proto1, 'VHTest', 'Test')
        self.assertIn(self.proto1, self.factory.virtual_hubs['VHTest'])

    def test_calc_join(self):
        self._join_hub(self.proto1, 'VHTest', 'Test')
        self._join_calc(self.proto1, '0123456789')
        self.assertIn('0123456789', self.proto1.calculators)

    def test_broadcast(self):
        self._join_hub(self.proto1, 'VHTest', 'Test1')
        self._join_hub(self.proto2, 'VHTest', 'Test2')
        self._join_calc(self.proto1, '0123456789')
        self._join_calc(self.proto2, '1234567890')

        msg = b'\x1a\x00babcdefghijklmnopqrstuvwxyz'
        self._send(self.proto1, 'b', msg[3:])

        self.assertEquals(self.tr1.value(), b'')
        self.assertEquals(self.tr2.value(), msg)

    def test_directed(self):
        self._join_hub(self.proto1, 'VHTest', 'Test1')
        self._join_hub(self.proto2, 'VHTest', 'Test2')
        self._join_calc(self.proto1, '0123456789')
        self._join_calc(self.proto2, '1234567890')

        # 'Y' From test1 to test2
        msg = b'\xff\x89\x12\x34\x56\x78\x90\x01\x23\x45\x67\x89\x01\x00Y\x2a'
        self._send(self.proto1, 'f', msg)

        self.assertEquals(self.tr2.value(), b'\x10\x00f' + msg)
        self.assertEquals(self.tr1.value(), '')

    def test_disconnect(self):
        self._join_hub(self.proto1, 'VHTest', 'Test1')
        self.proto1.transport.loseConnection()
        self.assertNotIn('VHTest', self.factory.virtual_hubs)