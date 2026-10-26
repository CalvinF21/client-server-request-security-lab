import json, unittest
from lab.security import make_signature, signature_matches, timestamp_is_fresh, safe_json_preview

class Tests(unittest.TestCase):
    def test_body_change_changes_signature(self):
        self.assertNotEqual(make_signature("1000","n",b"a","s"), make_signature("1000","n",b"b","s"))
    def test_constant_time_comparison_helper(self):
        a=make_signature("1000","n",b"a","s")
        self.assertTrue(signature_matches(a,a)); self.assertFalse(signature_matches(a,"0"*len(a)))
    def test_timestamp(self):
        self.assertTrue(timestamp_is_fresh("1000",now=1050)); self.assertFalse(timestamp_is_fresh("1000",now=2000))
        self.assertFalse(timestamp_is_fresh("bad",now=1000))
    def test_redaction(self):
        x=safe_json_preview(json.dumps({"authorization":"fake","nested":{"sessionid":"fake","label":"ok"}}).encode())
        self.assertEqual(x["authorization"],"[REDACTED]"); self.assertEqual(x["nested"]["sessionid"],"[REDACTED]")
        self.assertEqual(x["nested"]["label"],"ok")
    def test_malformed_body_does_not_echo_raw_text(self):
        x=safe_json_preview(b"sessionid=secret&token=abc")
        self.assertNotIn("secret",json.dumps(x)); self.assertIn("body_sha256",x)
if __name__ == "__main__": unittest.main()
