import hmac
import os
import struct
import unittest
import hashlib

from .base import TEST_ROOT_PATH

from collections import OrderedDict
from pyrad2 import packet
from pyrad2.client import Client
from pyrad2.dictionary import Dictionary
from pyrad2.constants import PacketType


class UtilityTests(unittest.TestCase):
    def testGenerateID(self):
        id = packet.create_id()
        self.assertTrue(isinstance(id, int))
        newid = packet.create_id()
        self.assertNotEqual(id, newid)


class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "simple"))

    def testBasicConstructor(self):
        pkt = self.klass()
        self.assertTrue(isinstance(pkt.code, int))
        self.assertTrue(isinstance(pkt.id, int))
        self.assertTrue(isinstance(pkt.secret, bytes))

    def testNamedConstructor(self):
        pkt = self.klass(
            code=26,
            id=38,
            secret=b"secret",
            authenticator=b"authenticator",
            dict="fakedict",
        )
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, b"secret")
        self.assertEqual(pkt.authenticator, b"authenticator")
        self.assertEqual(pkt.dict, "fakedict")

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        self.assertTrue(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.assertFalse(getattr(pkt, "fd", None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret="secret")

    def testConstructorWithAttributes(self):
        pkt = self.klass(**{"Test-String": "this works", "dict": self.dict})
        self.assertEqual(pkt["Test-String"], ["this works"])

    def testConstructorWithTlvAttribute(self):
        pkt = self.klass(
            **{"Test-Tlv-Str": "this works", "Test-Tlv-Int": 10, "dict": self.dict}
        )
        self.assertEqual(
            pkt["Test-Tlv"], {"Test-Tlv-Str": ["this works"], "Test-Tlv-Int": [10]}
        )


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))
        self.packet = packet.Packet(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def _create_reply_with_duplicate_attributes(self, request):
        """
        Creates a reply to the given request with multiple instances of the
        same attribute that also do not appear sequentially in the list. Used
        to ensure that methods providing authenticator and
        Message-Authenticator verification can handle the case where multiple
        instances of an given attribute do not appear sequentially in the
        attributes list.
        """
        # Manually build the packet since using packet.Packet will always group
        # attributes of the same type together
        attributes = self._get_attribute_bytes("Test-String", "test")
        attributes += self._get_attribute_bytes("Test-Integer", 1)
        attributes += self._get_attribute_bytes("Test-String", "test")
        attributes += self._get_attribute_bytes("Message-Authenticator", 16 * b"\00")

        header = struct.pack(
            "!BBH", PacketType.AccessAccept, request.id, (20 + len(attributes))
        )

        # Calculate the Message-Authenticator and update the attribute
        hmac_constructor = hmac.new(request.secret, None, hashlib.md5)
        hmac_constructor.update(header + request.authenticator + attributes)
        updated_message_authenticator = hmac_constructor.digest()
        attributes = attributes.replace(b"\x00" * 16, updated_message_authenticator)

        # Calculate the response authenticator
        authenticator = hashlib.md5(
            header + request.authenticator + attributes + request.secret
        ).digest()

        reply_bytes = header + authenticator + attributes
        return packet.AuthPacket(packet=reply_bytes, dict=self.dict)

    def _get_attribute_bytes(self, attr_name, value):
        attr = self.dict.attributes[attr_name]
        attr_key = attr.code
        attr_value = packet.tools.encode_attr(attr.type, value)
        attr_len = len(attr_value) + 2
        return struct.pack("!BB", attr_key, attr_len) + attr_value

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])

    def testAttributeAccess(self):
        self.packet["Test-Integer"] = 10
        self.assertEqual(self.packet["Test-Integer"], [10])
        self.assertEqual(self.packet[3], [b"\x00\x00\x00\x0a"])

        self.packet["Test-String"] = "dummy"
        self.assertEqual(self.packet["Test-String"], ["dummy"])
        self.assertEqual(self.packet[1], [b"dummy"])

    def testAttributeValueAccess(self):
        self.packet["Test-Integer"] = "Three"
        self.assertEqual(self.packet["Test-Integer"], ["Three"])
        self.assertEqual(self.packet[3], [b"\x00\x00\x00\x03"])

    def testVendorAttributeAccess(self):
        self.packet["Simplon-Number"] = 10
        self.assertEqual(self.packet["Simplon-Number"], [10])
        self.assertEqual(self.packet[(16, 1)], [b"\x00\x00\x00\x0a"])

        self.packet["Simplon-Number"] = "Four"
        self.assertEqual(self.packet["Simplon-Number"], ["Four"])
        self.assertEqual(self.packet[(16, 1)], [b"\x00\x00\x00\x04"])

    def testRawAttributeAccess(self):
        marker = [b""]
        self.packet[1] = marker
        self.assertTrue(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.assertTrue(self.packet[(16, 1)] is marker)

    def testEncryptedAttributes(self):
        self.packet["Test-Encrypted-String"] = "dummy"
        self.assertEqual(self.packet["Test-Encrypted-String"], ["dummy"])

        self.packet["Test-Encrypted-Integer"] = 10
        self.assertEqual(self.packet["Test-Encrypted-Integer"], [10])

    def testHasKey(self):
        self.assertEqual(self.packet.has_key("Test-String"), False)
        self.assertEqual("Test-String" in self.packet, False)
        self.packet["Test-String"] = "dummy"
        self.assertEqual(self.packet.has_key("Test-String"), True)
        self.assertEqual(self.packet.has_key(1), True)
        self.assertEqual(1 in self.packet, True)

    def testHasKeyWithUnknownKey(self):
        self.assertEqual(self.packet.has_key("Unknown-Attribute"), False)
        self.assertEqual("Unknown-Attribute" in self.packet, False)

    def testDelItem(self):
        self.packet["Test-String"] = "dummy"
        del self.packet["Test-String"]
        self.assertEqual(self.packet.has_key("Test-String"), False)
        self.packet["Test-String"] = "dummy"
        del self.packet[1]
        self.assertEqual(self.packet.has_key("Test-String"), False)

    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet["Test-String"] = "dummy"
        self.assertEqual(self.packet.keys(), ["Test-String"])
        self.packet["Test-Integer"] = 10
        self.assertEqual(self.packet.keys(), ["Test-String", "Test-Integer"])
        OrderedDict.__setitem__(self.packet, 12345, None)
        self.assertEqual(self.packet.keys(), ["Test-String", "Test-Integer", 12345])

    def test_create_authenticator(self):
        a = packet.Packet.create_authenticator()
        self.assertTrue(isinstance(a, bytes))
        self.assertEqual(len(a), 16)

        b = packet.Packet.create_authenticator()
        self.assertNotEqual(a, b)

    def testGenerateID(self):
        id = self.packet.create_id()
        self.assertTrue(isinstance(id, int))
        newid = self.packet.create_id()
        self.assertNotEqual(id, newid)

    def testReplyPacket(self):
        reply = self.packet.reply_packet()
        self.assertEqual(
            reply,
            (
                b"\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c"
                b"\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7"
            ),
        )

    def test_verify_reply(self):
        reply = self.packet.create_reply()
        self.assertEqual(self.packet.verify_reply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.id = self.packet.id

        reply.secret = b"different"
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = b"X" * 16
        self.assertEqual(self.packet.verify_reply(reply), False)
        reply.authenticator = self.packet.authenticator

    def test_verify_reply_duplicate_attributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        self.assertTrue(
            self.packet.verify_reply(reply=reply, rawreply=reply.raw_packet)
        )

    def test_verify_message_authenticator(self):
        reply = self.packet.create_reply(
            **{
                "Test-String": "test",
                "Test-Integer": 3,
            }
        )
        reply.code = PacketType.AccessAccept
        reply.add_message_authenticator()
        reply._refresh_message_authenticator()
        self.assertTrue(
            reply.verify_message_authenticator(
                secret=b"secret",
                original_authenticator=self.packet.authenticator,
                original_code=self.packet.code,
            )
        )

        self.assertFalse(
            reply.verify_message_authenticator(
                secret=b"bad_secret",
                original_authenticator=self.packet.authenticator,
                original_code=self.packet.code,
            )
        )

        self.assertFalse(
            reply.verify_message_authenticator(
                secret=b"secret",
                original_authenticator=b"bad_authenticator",
                original_code=self.packet.code,
            )
        )

    def testVerifyMessageAuthenticatorDuplicateAttributes(self):
        reply = self._create_reply_with_duplicate_attributes(self.packet)
        self.assertTrue(
            reply.verify_message_authenticator(
                secret=b"secret",
                original_authenticator=self.packet.authenticator,
                original_code=PacketType.AccessRequest,
            )
        )

    def testPktEncodeAttribute(self):
        encode = self.packet._pkt_encode_attribute

        # Encode a normal attribute
        self.assertEqual(encode(1, b"value"), b"\x01\x07value")
        # Encode a vendor attribute
        self.assertEqual(
            encode((1, 2), b"value"), b"\x1a\x0d\x00\x00\x00\x01\x02\x07value"
        )

    def testPktEncodeTlvAttribute(self):
        encode = self.packet._pkt_encode_tlv

        # Encode a normal tlv attribute
        self.assertEqual(
            encode(4, {1: [b"value"], 2: [b"\x00\x00\x00\x02"]}),
            b"\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02",
        )

        # Encode a normal tlv attribute with several sub attribute instances
        self.assertEqual(
            encode(4, {1: [b"value", b"other"], 2: [b"\x00\x00\x00\x02"]}),
            b"\x04\x16\x01\x07value\x02\x06\x00\x00\x00\x02\x01\x07other",
        )
        # Encode a vendor tlv attribute
        self.assertEqual(
            encode((16, 3), {1: [b"value"], 2: [b"\x00\x00\x00\x02"]}),
            b"\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02",
        )

    def testPktEncodeLongTlvAttribute(self):
        encode = self.packet._pkt_encode_tlv

        long_str = b"a" * 245
        # Encode a long tlv attribute - check it is split between AVPs
        self.assertEqual(
            encode(4, {1: [b"value", long_str], 2: [b"\x00\x00\x00\x02"]}),
            b"\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x02\x04\xf9\x01\xf7" + long_str,
        )

        # Encode a long vendor tlv attribute
        first_avp = (
            b"\x1a\x15\x00\x00\x00\x10\x03\x0f\x01\x07value\x02\x06\x00\x00\x00\x02"
        )
        second_avp = b"\x1a\xff\x00\x00\x00\x10\x03\xf9\x01\xf7" + long_str
        self.assertEqual(
            encode((16, 3), {1: [b"value", long_str], 2: [b"\x00\x00\x00\x02"]}),
            first_avp + second_avp,
        )

    def testPktEncodeAttributes(self):
        self.packet[1] = [b"value"]
        self.assertEqual(self.packet._pkt_encode_attributes(), b"\x01\x07value")

        self.packet.clear()
        self.packet[(16, 2)] = [b"value"]
        self.assertEqual(
            self.packet._pkt_encode_attributes(),
            b"\x1a\x0d\x00\x00\x00\x10\x02\x07value",
        )

        self.packet.clear()
        self.packet[1] = [b"one", b"two", b"three"]
        self.assertEqual(
            self.packet._pkt_encode_attributes(), b"\x01\x05one\x01\x05two\x01\x07three"
        )

        self.packet.clear()
        self.packet[1] = [b"value"]
        self.packet[(16, 2)] = [b"value"]
        self.assertEqual(
            self.packet._pkt_encode_attributes(),
            b"\x01\x07value\x1a\x0d\x00\x00\x00\x10\x02\x07value",
        )

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._pkt_decode_vendor_attribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(b""), [(26, b"")])
        self.assertEqual(decode(b"12345"), [(26, b"12345")])

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(
            decode(b"\x00\x00\x00\x01\x02\x06value"),
            [(26, b"\x00\x00\x00\x01\x02\x06value")],
        )

        # Proper RFC2865 recommended form
        self.assertEqual(
            decode(b"\x00\x00\x00\x10\x02\x07value"), [((16, 2), b"value")]
        )

    def testPktDecodeTlvAttribute(self):
        decode = self.packet._pkt_decode_tlv_attribute

        decode(4, b"\x01\x07value")
        self.assertEqual(self.packet[4], {1: [b"value"]})

        # add another instance of the same sub attribute
        decode(4, b"\x01\x07other")
        self.assertEqual(self.packet[4], {1: [b"value", b"other"]})

        # add a different sub attribute
        decode(4, b"\x02\x07\x00\x00\x00\x01")
        self.assertEqual(
            self.packet[4], {1: [b"value", b"other"], 2: [b"\x00\x00\x00\x01"]}
        )

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.decode_packet(b"")
        except packet.PacketError as e:
            self.assertTrue("header is corrupt" in str(e))
        else:
            self.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.decode_packet(b"\x00\x00\x00\x001234567890123456")
        except packet.PacketError as e:
            self.assertTrue("invalid length" in str(e))
        else:
            self.fail()

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.decode_packet(b"\x00\x00\x24\x00" + (0x2400 - 4) * b"X")
        except packet.PacketError as e:
            self.assertTrue("too long" in str(e))
        else:
            self.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.decode_packet(b"\x01\x02\x00\x151234567890123456\x00")
        except packet.PacketError as e:
            self.assertTrue("header is corrupt" in str(e))
        else:
            self.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.decode_packet(b"\x01\x02\x00\x141234567890123456")
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, b"1234567890123456")
        self.assertEqual(self.packet.keys(), [])

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.decode_packet(b"\x01\x02\x00\x161234567890123456\x00\x01")
        except packet.PacketError as e:
            self.assertTrue("too small" in str(e))
        else:
            self.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x161234567890123456\x01\x02")
        self.assertEqual(self.packet[1], [b""])

    def testDecodePacketWithAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x01\x07value")
        self.assertEqual(self.packet[1], [b"value"])

    def testDecodePacketWithUnknownAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x09\x07value")
        self.assertEqual(self.packet[9], [b"value"])

    def testDecodePacketWithTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value"
        )
        self.assertEqual(self.packet[4], {1: [b"value"]})

    def testDecodePacketIsTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1d1234567890123456\x04\x09\x01\x07value"
        )
        self.assertTrue(self.packet._pkt_is_tlv_attribute(4))

    def testDecodePacketWithVendorTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x231234567890123456\x1a\x0f\x00\x00\x00\x10\x03\x09\x01\x07value"
        )
        self.assertEqual(self.packet[(16, 3)], {1: [b"value"]})

    def testDecodePacketWithTlvAttributeWith2SubAttributes(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x231234567890123456\x04\x0f\x01\x07value\x02\x06\x00\x00\x00\x09"
        )
        self.assertEqual(self.packet[4], {1: [b"value"], 2: [b"\x00\x00\x00\x09"]})

    def testDecodePacketWithSplitTlvAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x251234567890123456\x04\x09\x01\x07value\x04\x09\x02\x06\x00\x00\x00\x09"
        )
        self.assertEqual(self.packet[4], {1: [b"value"], 2: [b"\x00\x00\x00\x09"]})

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two"
        )
        self.assertEqual(self.packet[1], [b"one", b"two"])

    def testDecodePacketWithTwoAttributes(self):
        self.packet.decode_packet(
            b"\x01\x02\x00\x1e1234567890123456\x01\x05one\x01\x05two"
        )
        self.assertEqual(self.packet[1], [b"one", b"two"])

    def testDecodePacketWithVendorAttribute(self):
        self.packet.decode_packet(b"\x01\x02\x00\x1b1234567890123456\x1a\x07value")
        self.assertEqual(self.packet[26], [b"value"])

    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._encode_key_values(1, "1234"), (1, "1234"))

    def testEncodeKey(self):
        self.assertEqual(self.packet._encode_key(1), 1)

    def testadd_attribute(self):
        self.packet.add_attribute("Test-String", "1")
        self.assertEqual(self.packet["Test-String"], ["1"])
        self.packet.add_attribute("Test-String", "1")
        self.assertEqual(self.packet["Test-String"], ["1", "1"])
        self.packet.add_attribute("Test-String", ["2", "3"])
        self.assertEqual(self.packet["Test-String"], ["1", "1", "2", "3"])


class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, PacketType.AccessRequest)


class AuthPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "full"))
        self.packet = packet.AuthPacket(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        self.assertEqual(reply.code, PacketType.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])

    def testRequestPacket(self):
        self.assertEqual(
            self.packet.request_packet(), b"\x01\x00\x00\x1401234567890ABCDE"
        )

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.request_packet()
        self.assertTrue(self.packet.authenticator is not None)

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.request_packet()
        self.assertTrue(self.packet.id is not None)

    def testpw_cryptEmptyPassword(self):
        self.assertEqual(self.packet.pw_crypt(""), b"")

    def testpw_cryptPassword(self):
        self.assertEqual(
            self.packet.pw_crypt("Simplon"),
            b"\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01",
        )

    def testpw_cryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.pw_crypt("")
        self.assertTrue(self.packet.authenticator is not None)

    def testpw_decryptEmptyPassword(self):
        self.assertEqual(self.packet.pw_decrypt(b""), "")

    def testpw_decryptPassword(self):
        self.assertEqual(
            self.packet.pw_decrypt(b"\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01"),
            "Simplon",
        )


class AuthPacketChapTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = Dictionary(os.path.join(self.path, "chap"))
        # self.packet = packet.Packet(id=0, secret=b'secret',
        #                             dict=self.dict)
        self.client = Client(server="localhost", secret=b"secret", dict=self.dict)

    def testVerifyChapPasswd(self):
        chap_id = b"9"
        chap_challenge = b"987654321"
        chap_password = (
            chap_id + hashlib.md5(chap_id + b"test_password" + chap_challenge).digest()
        )
        pkt = self.client.create_auth_packet(
            code=PacketType.AccessChallenge,
            authenticator=b"ABCDEFG",
            User_Name="test_name",
            CHAP_Challenge=chap_challenge,
            CHAP_Password=chap_password,
        )
        self.assertEqual(pkt["CHAP-Challenge"][0], chap_challenge)
        self.assertEqual(pkt["CHAP-Password"][0], chap_password)
        self.assertEqual(pkt.verify_chap_passwd("test_password"), True)


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, PacketType.AccountingRequest)

    def testConstructorRawPacket(self):
        raw = (
            b"\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c"
            b"\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7"
        )
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(TEST_ROOT_PATH, "data")
        self.dict = self.loadDict()
        self.packet = packet.AcctPacket(
            id=0, secret=b"secret", authenticator=b"01234567890ABCDEF", dict=self.dict
        )

    def loadDict(self, filename="full"):
        return Dictionary(os.path.join(self.path, filename))

    def test_create_reply(self):
        reply = self.packet.create_reply(**{"Test-Integer": 10})
        self.assertEqual(reply.code, PacketType.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply["Test-Integer"], [10])

    def test_verify_acct_request(self):
        rawpacket = self.packet.request_packet()
        pkt = packet.AcctPacket(secret=b"secret", packet=rawpacket)
        self.assertEqual(pkt.verify_acct_request(), True)

        pkt.secret = b"different"
        self.assertEqual(pkt.verify_acct_request(), False)
        pkt.secret = b"secret"

        pkt.raw_packet = b"X" + pkt.raw_packet[1:]
        self.assertEqual(pkt.verify_acct_request(), False)

    def testRequestPacket(self):
        self.assertEqual(
            self.packet.request_packet(),
            b"\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f",
        )

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.request_packet()
        self.assertTrue(self.packet.id is not None)

    def testRealisticUnknownAttributes(self):
        """Test a realistic Accounting Packet from raw
        User-Name: [u'user@example.com']
        NAS-IP-Address: ['1.2.3.4']
        Service-Type: ['Framed-User']
        Framed-Protocol: ['NAS-Prompt-User']
        Framed-IP-Address: ['1.2.3.4']
        Acct-Status-Type: ['Interim-Update']
        Acct-Delay-Time: [0]
        Acct-Input-Octets: [1290826858]
        Acct-Output-Octets: [3551101035]
        Acct-Session-Id: [u'90dbd65a18b0a6c']
        Acct-Authentic: ['RADIUS']
        Acct-Session-Time: [769500]
        Acct-Input-Packets: [7403861]
        Acct-Output-Packets: [10928170]
        Acct-Link-Count: [1]
        Acct-Input-Gigawords: [0]
        Acct-Output-Gigawords: [2]
        Event-Timestamp: [1554155989]
        # vendor specific
        NAS-Port-Type: ['Virtual']
        (26, 594, 1): [u'UNKNOWN_PRODUCT']
        # implementation specific fields
        224: ['24P\x10\x00\x22\x96\xc9']
        228: ['\xfe\x99\xd0P']
        """
        raw = (
            b"\x04\x8e\x00\xc4\xb2\xf8z\xdb\xac\xfd9l\x9dI?E\x8c%\xe9"
            b"\xf5\x01\x12user@example.com\x04\x06\x01\x02\x03\x04\x06\x06"
            b"\x00\x00\x00\x02\x07\x06\x00\x00\x00\x07\x08\x06\x01\x02\x03"
            b"\x04(\x06\x00\x00\x00\x03)\x06\x00\x00\x00\x00*\x06L\xf0tj+"
            b"\x06\xd3\xa9\x80k,\x1190dbd65a18b0a6c-\x06\x00\x00\x00\x01."
            b"\x06\x00\x0b\xbd\xdc/\x06\x00p\xf9U0\x06\x00\xa6\xc0*3\x06"
            b"\x00\x00\x00\x014\x06\x00\x00\x00\x005\x06\x00\x00\x00\x027"
            b"\x06\\\xa2\x89\xd5=\x06\x00\x00\x00\x05\x1a\x17\x00\x00\x02R"
            b"\x01\x11UNKNOWN_PRODUCT\xe0\n24P\x10\x00\x22\x96\xc9\xe4\x06"
            b"\xfe\x99\xd0P"
        )
        pkt = packet.AcctPacket(dict=self.loadDict("realistic"), packet=raw)
        self.assertEqual(pkt.raw_packet, raw)

        self.assertEqual(pkt.code, PacketType.AccountingRequest)
        self.assertEqual(pkt["User-Name"], ["user@example.com"])
        self.assertEqual(pkt["NAS-IP-Address"], ["1.2.3.4"])
        self.assertEqual(pkt["Acct-Status-Type"], ["Interim-Update"])
        self.assertEqual(pkt["Acct-Session-Id"], ["90dbd65a18b0a6c"])
        self.assertEqual(pkt["Acct-Authentic"], ["RADIUS"])

        # Unknown attributes preserved
        self.assertEqual(pkt[224][0], b"24P\x10\x00\x22\x96\xc9")
        self.assertEqual(pkt[228][0], b"\xfe\x99\xd0P")

        # Vendor unknown preserved
        self.assertEqual(pkt[(594, 1)], [b"UNKNOWN_PRODUCT"])

        raw_no_authenticator = raw[:4] + b"\x00" * 16 + raw[20:]
        rebuilt = pkt.request_packet()
        rebuilt_no_authenticator = rebuilt[:4] + b"\x00" * 16 + rebuilt[20:]

        self.assertEqual(raw_no_authenticator, rebuilt_no_authenticator)
