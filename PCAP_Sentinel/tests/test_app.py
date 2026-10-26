import io
import unittest

import app as app_module
from tests.pcap_factory import PcapBuilder, T0, background_traffic, tcp_conversation


class FlaskTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def post(self, data, name="x.pcap"):
        return self.client.post("/api/analyze", data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")

    def test_index_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"PCAP Sentinel", r.data)

    def test_valid_upload_with_and_without_findings(self):
        b = PcapBuilder(); background_traffic(b, T0, 3)
        r = self.post(b.to_bytes(), "../../evil name.pcap")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["findings"], [])
        self.assertEqual(body["capture"]["filename"], "evil_name.pcap")           # path components stripped
        self.assertEqual(self.post(b.to_bytes(pcapng=True), "y.pcapng").status_code, 200)

    def test_rejections(self):
        self.assertEqual(self.client.post("/api/analyze").status_code, 400)
        self.assertEqual(self.post(b"x", "notes.txt").status_code, 400)
        bad = self.post(b"this is definitely not a capture", "fake.pcap")
        self.assertEqual(bad.status_code, 400)
        self.assertIn("not a readable capture", bad.get_json()["error"])

    def test_truncated_capture_is_accepted_with_a_warning(self):
        b = PcapBuilder(); tcp_conversation(b, T0, "10.0.0.1", 4000, "10.0.0.2", 80)
        r = self.post(b.to_bytes()[:-5])
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["statistics"]["data_quality"]["file_truncated"])

    def test_upload_size_limit(self):
        old = app_module.app.config["MAX_CONTENT_LENGTH"]
        app_module.app.config["MAX_CONTENT_LENGTH"] = 1000
        try:
            r = self.post(b"\x00" * 5000)
            self.assertEqual(r.status_code, 413)
            self.assertIn("error", r.get_json())
        finally:
            app_module.app.config["MAX_CONTENT_LENGTH"] = old


if __name__ == "__main__":
    unittest.main()
