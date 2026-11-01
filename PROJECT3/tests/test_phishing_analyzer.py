import http.client, json, os, sys, threading, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app, keyword_detector, risk_scorer, url_analyzer
from phishing_analyzer import analyze, InputError

BANK = "Your HDFC Bank account has been suspended due to unusual activity. Verify your login credentials immediately: http://hdfcbank-secure-login.top/verify to avoid permanent closure. Act now."
LEGIT = "Hi Asha, your order #48213 has shipped. Track it at https://www.amazon.com/your-orders. We will never ask for your password or OTP."


class AnalyzerTests(unittest.TestCase):
    def test_empty_and_wrong_type(self):
        for bad in ["", "   ", None, 42]:
            with self.assertRaises(InputError): analyze(bad)

    def test_oversized(self):
        with self.assertRaises(InputError) as c: analyze("a" * 10001)
        self.assertEqual(c.exception.status, 413)

    def test_legitimate_is_low(self):
        r = analyze(LEGIT); self.assertEqual(r["level"], "Low Risk"); self.assertLess(r["score"], 25)

    def test_obvious_phishing_is_critical(self):
        r = analyze(BANK); self.assertEqual(r["level"], "Critical Risk"); self.assertLessEqual(r["score"], 100)

    def test_url_extraction_trims_punctuation(self):
        self.assertEqual(url_analyzer.extract_urls("See http://a.com/x, and www.b.org."), ["http://a.com/x", "www.b.org"])

    def test_ip_and_shortener(self):
        self.assertIn("ip", [i["id"] for i in url_analyzer.analyze_url("http://45.33.12.9/claim")["indicators"]])
        self.assertIn("shortener", [i["id"] for i in url_analyzer.analyze_url("https://bit.ly/abc")["indicators"]])

    def test_clean_https_url_not_flagged(self):
        u = url_analyzer.analyze_url("https://www.amazon.com/your-orders"); self.assertEqual(u["indicators"], [])

    def test_lookalike_domain(self):
        self.assertIn("lookalike", [i["id"] for i in url_analyzer.analyze_url("https://paypa1.com/login")["indicators"]])

    def test_keyword_detection_and_negation(self):
        self.assertIn("otp_request", [k["rule_id"] for k in keyword_detector.detect_keywords("Please share your OTP now")])
        self.assertEqual(keyword_detector.detect_keywords("We will never ask you to share your OTP."), [])

    def test_social_engineering(self):
        techs = [t["technique"] for t in analyze(BANK)["social_engineering"]]
        for t in ("Urgency / panic", "Impersonating a trusted organisation", "Requesting sensitive information"): self.assertIn(t, techs)

    def test_score_boundaries(self):
        for s, lvl in [(0, "Low Risk"), (24, "Low Risk"), (25, "Moderate Risk"), (49, "Moderate Risk"), (50, "High Risk"), (74, "High Risk"), (75, "Critical Risk"), (100, "Critical Risk")]:
            self.assertEqual(risk_scorer.classify(s), lvl)

    def test_breakdown_sums_to_score_and_no_double_count(self):
        r = analyze(BANK + " " + BANK)
        self.assertEqual(r["score"], min(100, sum(b["points"] for b in r["breakdown"])))
        self.assertEqual(len(r["urls"]), 1)


class RegressionTests(unittest.TestCase):
    """Bugs found during browser QA."""
    def test_bare_domain_extracted_but_not_email(self):
        urls = url_analyzer.extract_urls("Visit paypal-login.top/verify or mail help@gmail.com")
        self.assertEqual(urls, ["paypal-login.top/verify"])

    def test_negation_does_not_hide_real_phishing(self):
        for msg in ["Do not delay: verify your password now", "You will never regain access unless you verify your password"]:
            self.assertIn("cred_request", [k["rule_id"] for k in keyword_detector.detect_keywords(msg)])

    def test_legit_security_notices_stay_low(self):
        for msg in ["123456 is your OTP. Do not share your OTP with anyone.", "We will never ask you to share your OTP."]:
            self.assertEqual(analyze(msg)["level"], "Low Risk")

    def test_scores_rise_with_more_signals(self):
        msgs = ["Your order shipped.", "Your order: http://amazon-track.xyz/o", "Your Amazon account has been suspended. Act now! Verify your password and enter your OTP at http://45.1.2.3/login"]
        s = [analyze(m)["score"] for m in msgs]
        self.assertTrue(s[0] < s[1] < s[2], s)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = app.make_server(0); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); cls.srv.server_close()

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port); c.request(method, path, body, {"Content-Type": "application/json"})
        r = c.getresponse(); data = r.read(); c.close(); return r.status, data

    def test_health_and_static(self):
        self.assertEqual(self.call("GET", "/api/health")[0], 200)
        self.assertEqual(self.call("GET", "/")[0], 200)
        self.assertEqual(self.call("GET", "/../app.py")[0], 404)

    def test_other_methods_return_json_405(self):
        for m in ["PUT", "DELETE", "OPTIONS", "GET"]:
            code, data = self.call(m, "/api/analyze", "{}" if m != "GET" else None)
            self.assertEqual(code, 405); self.assertIn("error", json.loads(data))

    def test_malformed_requests(self):
        self.assertEqual(self.call("POST", "/api/analyze", "{bad")[0], 400)
        self.assertEqual(self.call("POST", "/api/analyze", "[1]")[0], 400)
        self.assertEqual(self.call("POST", "/api/analyze", json.dumps({"message": ""}))[0], 400)
        self.assertEqual(self.call("POST", "/api/analyze", json.dumps({"message": 5}))[0], 400)

    def test_valid_analysis(self):
        s, d = self.call("POST", "/api/analyze", json.dumps({"message": BANK}))
        self.assertEqual(s, 200); self.assertEqual(json.loads(d)["level"], "Critical Risk")


if __name__ == "__main__":
    unittest.main(verbosity=2)
