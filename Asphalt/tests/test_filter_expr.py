import unittest

from utils.filtering import compile_packet_filter


class FilterExprTests(unittest.TestCase):
    def setUp(self):
        self.packet = {
            "ip_version": 4,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 443,
            "l4_protocol": "TCP",
            "tcp_flags_names": ["SYN", "ACK"],
            "dns_qname": "example.com",
            "dns_rcode": 3,
        }

    def test_l4_tcp_and_port(self):
        pred = compile_packet_filter("l4=tcp and dst_port=443")
        self.assertTrue(pred(self.packet))

    def test_app_dns_and_rcode(self):
        pred = compile_packet_filter("app=dns and dns_rcode=NXDOMAIN")
        self.assertTrue(pred(self.packet))

    def test_not_ipv6(self):
        pred = compile_packet_filter("not l3=ipv6")
        self.assertTrue(pred(self.packet))

    def test_tcp_flag(self):
        pred = compile_packet_filter("tcp_flag=syn")
        self.assertTrue(pred(self.packet))


if __name__ == "__main__":
    unittest.main()
