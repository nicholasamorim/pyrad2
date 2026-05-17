import unittest
import ssl

from pyrad2 import tools

from .base import TEST_ROOT_PATH


class EncodingTests(unittest.TestCase):
    def test_string_encoding(self):
        self.assertRaises(ValueError, tools.encode_string, "x" * 254)
        self.assertEqual(tools.encode_string("1234567890"), b"1234567890")

    def test_invalid_string_encoding_raises_type_error(self):
        self.assertRaises(TypeError, tools.encode_string, 1)

    def test_address_encoding(self):
        self.assertRaises((ValueError, Exception), tools.encode_address, "TEST123")
        self.assertEqual(tools.encode_address("192.168.0.255"), b"\xc0\xa8\x00\xff")

    def test_invalid_address_encoding_raises_type_error(self):
        self.assertRaises(TypeError, tools.encode_address, 1)

    def test_integer_encoding(self):
        self.assertEqual(tools.encode_integer(0x01020304), b"\x01\x02\x03\x04")

    def test_integer64_encoding(self):
        self.assertEqual(tools.encode_integer64(0xFFFFFFFFFFFFFFFF), b"\xff" * 8)

    def test_unsigned_integer_encoding(self):
        self.assertEqual(tools.encode_integer(0xFFFFFFFF), b"\xff\xff\xff\xff")

    def test_invalid_integer_encoding_raises_type_error(self):
        self.assertRaises(TypeError, tools.encode_integer, "ONE")

    def test_date_encoding(self):
        self.assertEqual(tools.encode_date(0x01020304), b"\x01\x02\x03\x04")

    def test_invalid_data_encoding_raises_type_error(self):
        self.assertRaises(TypeError, tools.encode_date, "1")

    def test_encode_ascend_binary(self):
        self.assertEqual(
            tools.encode_ascend_binary(
                "family=ipv4 action=discard direction=in dst=10.10.255.254/32"
            ),
            b"\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

    def test_string_decoding(self):
        self.assertEqual(tools.decode_string(b"1234567890"), "1234567890")

    def test_address_decoding(self):
        self.assertEqual(tools.decode_address(b"\xc0\xa8\x00\xff"), "192.168.0.255")

    def test_integer_decoding(self):
        self.assertEqual(tools.decode_integer(b"\x01\x02\x03\x04"), 0x01020304)

    def test_integer64_decoding(self):
        self.assertEqual(tools.decode_integer64(b"\xff" * 8), 0xFFFFFFFFFFFFFFFF)

    def test_date_decoding(self):
        self.assertEqual(tools.decode_date(b"\x01\x02\x03\x04"), 0x01020304)

    def test_octets_encoding(self):
        self.assertEqual(tools.encode_octets("0x01020304"), b"\x01\x02\x03\x04")
        self.assertEqual(tools.encode_octets(b"0x01020304"), b"\x01\x02\x03\x04")
        self.assertEqual(tools.encode_octets("16909060"), b"\x01\x02\x03\x04")
        # encodes to 253 bytes
        self.assertEqual(
            tools.encode_octets(
                "0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D"
            ),
            b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r",
        )
        self.assertRaisesRegex(
            ValueError,
            "Can only encode strings of <= 253 characters",
            tools.encode_octets,
            "0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E",
        )

    def test_ifid_encoding_roundtrip(self):
        text = "0011:2233:4455:6677"
        raw = tools.encode_ifid(text)
        self.assertEqual(raw, b"\x00\x11\x22\x33\x44\x55\x66\x77")
        self.assertEqual(tools.decode_ifid(raw), text)

    def test_ifid_encoding_passes_through_8_byte_input(self):
        raw = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        self.assertEqual(tools.encode_ifid(raw), raw)

    def test_ifid_encoding_rejects_bad_input(self):
        self.assertRaises(ValueError, tools.encode_ifid, "0011:2233:4455")
        self.assertRaises(ValueError, tools.encode_ifid, "zzzz:0000:0000:0000")
        self.assertRaises(ValueError, tools.encode_ifid, "10000:0:0:0")
        self.assertRaises(ValueError, tools.encode_ifid, b"\x00" * 4)
        self.assertRaises(TypeError, tools.encode_ifid, 42)

    def test_ifid_decoding_rejects_wrong_length(self):
        self.assertRaises(ValueError, tools.decode_ifid, b"\x00" * 6)

    def test_ether_encoding_roundtrip(self):
        text = "aa:bb:cc:dd:ee:ff"
        raw = tools.encode_ether(text)
        self.assertEqual(raw, b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(tools.decode_ether(raw), text)

    def test_ether_encoding_accepts_hyphen_separator(self):
        self.assertEqual(
            tools.encode_ether("AA-BB-CC-DD-EE-FF"),
            b"\xaa\xbb\xcc\xdd\xee\xff",
        )

    def test_ether_encoding_passes_through_6_byte_input(self):
        raw = b"\x01\x02\x03\x04\x05\x06"
        self.assertEqual(tools.encode_ether(raw), raw)

    def test_ether_encoding_rejects_bad_input(self):
        self.assertRaises(ValueError, tools.encode_ether, "aa:bb:cc:dd:ee")
        self.assertRaises(ValueError, tools.encode_ether, "zz:bb:cc:dd:ee:ff")
        self.assertRaises(TypeError, tools.encode_ether, 42)

    def test_ether_decoding_rejects_wrong_length(self):
        self.assertRaises(ValueError, tools.decode_ether, b"\x00" * 4)

    def test_unknown_type_encoding(self):
        self.assertRaises(ValueError, tools.encode_attr, "unknown", None)

    def test_unknown_type_decoding(self):
        self.assertRaises(ValueError, tools.decode_attr, "unknown", None)

    def test_normalize_cert_fingerprint(self):
        fingerprint = "SHA256:AA:BB " + ("cc" * 29) + "dd"
        self.assertEqual(
            tools.normalize_cert_fingerprint(fingerprint),
            "aabb" + ("cc" * 29) + "dd",
        )

    def test_normalize_cert_fingerprint_rejects_invalid_values(self):
        self.assertRaises(ValueError, tools.normalize_cert_fingerprint, "abc")
        self.assertRaises(ValueError, tools.normalize_cert_fingerprint, "z" * 64)

    def test_cert_fingerprint_matches_allowlist(self):
        with open(f"{TEST_ROOT_PATH}/certs/client/client.cert.pem") as cert_file:
            cert = ssl.PEM_cert_to_DER_cert(cert_file.read())

        fingerprint = tools.get_cert_fingerprint(cert)

        self.assertTrue(tools.cert_fingerprint_matches(cert, {fingerprint}))
        self.assertFalse(tools.cert_fingerprint_matches(cert, {"0" * 64}))

    def test_encode_function(self):
        self.assertEqual(tools.encode_attr("string", "string"), b"string")
        self.assertEqual(tools.encode_attr("octets", b"string"), b"string")
        self.assertEqual(
            tools.encode_attr("ipaddr", "192.168.0.255"), b"\xc0\xa8\x00\xff"
        )
        self.assertEqual(tools.encode_attr("integer", 0x01020304), b"\x01\x02\x03\x04")
        self.assertEqual(tools.encode_attr("date", 0x01020304), b"\x01\x02\x03\x04")
        self.assertEqual(
            tools.encode_attr("integer64", 0xFFFFFFFFFFFFFFFF), b"\xff" * 8
        )
        self.assertEqual(
            tools.encode_attr("ifid", "0011:2233:4455:6677"),
            b"\x00\x11\x22\x33\x44\x55\x66\x77",
        )
        self.assertEqual(
            tools.encode_attr("ether", "aa:bb:cc:dd:ee:ff"),
            b"\xaa\xbb\xcc\xdd\xee\xff",
        )

    def test_decode_function(self):
        self.assertEqual(tools.decode_attr("string", b"string"), "string")
        self.assertEqual(tools.encode_attr("octets", b"string"), b"string")
        self.assertEqual(
            tools.decode_attr("ipaddr", b"\xc0\xa8\x00\xff"), "192.168.0.255"
        )
        self.assertEqual(tools.decode_attr("integer", b"\x01\x02\x03\x04"), 0x01020304)
        self.assertEqual(
            tools.decode_attr("integer64", b"\xff" * 8), 0xFFFFFFFFFFFFFFFF
        )
        self.assertEqual(tools.decode_attr("date", b"\x01\x02\x03\x04"), 0x01020304)
        self.assertEqual(
            tools.decode_attr("ifid", b"\x00\x11\x22\x33\x44\x55\x66\x77"),
            "0011:2233:4455:6677",
        )
        self.assertEqual(
            tools.decode_attr("ether", b"\xaa\xbb\xcc\xdd\xee\xff"),
            "aa:bb:cc:dd:ee:ff",
        )
