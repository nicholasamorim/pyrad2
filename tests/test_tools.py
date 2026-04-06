import unittest

from pyrad2 import tools


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

    def test_unknown_type_encoding(self):
        self.assertRaises(ValueError, tools.encode_attr, "unknown", None)

    def test_unknown_type_decoding(self):
        self.assertRaises(ValueError, tools.decode_attr, "unknown", None)

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
