"""Builds the human-readable report text, summary and recommendations."""
DISCLAIMER = "This score is a heuristic assessment from a rule-based engine (no machine learning). It is not a guarantee that a message is safe or malicious."
RECS = {
 "Low Risk": ["No strong phishing signals found, but stay cautious with unexpected requests.", "Open sites by typing the address yourself rather than using links.", "Never share passwords or OTPs."],
 "Moderate Risk": ["Do not click links until you verify the sender through an official channel.", "Check the domain carefully before entering any information.", "Contact the organisation using its official app or website."],
 "High Risk": ["Do not click links, open attachments or reply.", "Never share passwords, OTPs, PINs or card details.", "Verify via the organisation's official contact details, not those in the message.", "Report and delete the message."],
 "Critical Risk": ["Do NOT click, reply, call listed numbers or pay anything.", "If you already interacted: change passwords, enable 2FA, contact your bank, monitor accounts.", "Report to your IT/security team, bank or national cyber-crime portal, then delete the message."],
}


def make_summary(score, level, kw, urls, techs):
    return "%s (%d/100). Found %d suspicious phrase(s), %d link(s) and %d manipulation technique(s)." % (level, score, len(kw), len(urls), len(techs))


def build_text_report(r):
    L = ["PHISHGUARD ANALYSIS REPORT", "=" * 40, "Generated: " + r["analyzed_at"], "Message preview: " + r["preview"],
         "Risk score: %d/100 - %s" % (r["score"], r["level"]), "", r["summary"], "", "SCORE BREAKDOWN"]
    L += ["  +%d  [%s] %s" % (b["points"], b["source"], b["label"]) for b in r["breakdown"]] or ["  (no indicators)"]
    L += ["", "SUSPICIOUS PHRASES"] + ["  - \"%s\" [%s]: %s" % (k["phrase"], k["category"], k["why"]) for k in r["keywords"]]
    L += ["", "URL ANALYSIS"] + ["  - %s -> %s: %s" % (u["url"], u["risk_level"], u["explanation"]) for u in r["urls"]]
    L += ["", "SOCIAL ENGINEERING"] + ["  - %s: %s" % (t["technique"], t["why"]) for t in r["social_engineering"]]
    L += ["", "RECOMMENDED ACTIONS"] + ["  * " + x for x in r["recommendations"]]
    L += ["", DISCLAIMER]
    return "\n".join(L)
