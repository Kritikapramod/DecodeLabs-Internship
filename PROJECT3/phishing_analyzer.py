"""Orchestrator: validate -> detect keywords -> analyse URLs -> social engineering -> score -> report."""
from datetime import datetime
import keyword_detector, url_analyzer, risk_scorer, report_generator as rg

MAX_LEN = 10000
RULE_TECHNIQUE = {"urgent_action": "Urgency / panic", "limited_time": "Urgency / panic", "account_threat": "Threatening account suspension",
    "payment_issue": "Fear of financial loss", "bank_blocked": "Fear of financial loss", "cred_request": "Requesting sensitive information",
    "otp_request": "Requesting sensitive information", "sensitive_info": "Requesting sensitive information",
    "reward": "Unrealistic rewards", "advance_fee": "Upfront payment demand", "click_cta": "Pressure to click a link"}
TECH_WHY = {"Urgency / panic": "Time pressure reduces careful checking.", "Threatening account suspension": "Fear of losing access makes people comply.",
    "Fear of financial loss": "Money-related alarms override caution.", "Requesting sensitive information": "Real organisations do not collect credentials or OTPs by message.",
    "Unrealistic rewards": "Too-good-to-be-true offers lure victims.", "Upfront payment demand": "Advance fees are a hallmark of job and parcel scams.",
    "Pressure to click a link": "Direct instructions to click deliver the attack.", "Impersonating a trusted organisation": "Borrowed brand names create false trust.",
    "Suspicious link presented": "A risky-looking link is offered as the solution."}


class InputError(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg); self.status = status


def analyze(message):
    if not isinstance(message, str):
        raise InputError("'message' must be a text string.")
    text = message.replace("\x00", "").strip()
    if not text:
        raise InputError("Message is empty. Paste some text to analyse.")
    if len(text) > MAX_LEN:
        raise InputError("Message too long (limit %d characters)." % MAX_LEN, 413)
    kws = keyword_detector.detect_keywords(text)
    urls = [url_analyzer.analyze_url(u) for u in url_analyzer.extract_urls(text)]
    impersonated = any(i["id"] in url_analyzer.IMPERSONATION_IDS for u in urls for i in u["indicators"])
    extra, mismatch = [], []
    if urls and not impersonated:  # brand named in text but links point elsewhere
        for b in url_analyzer.find_brands(text):
            if not any(u["registered"] in url_analyzer.BRANDS[b][1] for u in urls):
                mismatch.append(b)
        if mismatch:
            extra.append({"source": "Brand mismatch", "label": "Mentions %s but links to an unrelated domain" % mismatch[0], "points": 15})
    techs = {}
    for k in kws:
        t = RULE_TECHNIQUE.get(k["rule_id"])
        if t: techs.setdefault(t, k["phrase"])
    if impersonated or mismatch:
        if mismatch:
            techs["Impersonating a trusted organisation"] = "mentions " + mismatch[0] + " but links elsewhere"
        else:
            hit = next((u["domain"] + ": " + i["label"] for u in urls for i in u["indicators"] if i["id"] in url_analyzer.IMPERSONATION_IDS), "")
            techs["Impersonating a trusted organisation"] = hit
    if any(u["score"] >= 10 for u in urls):
        techs["Suspicious link presented"] = next(u["url"] for u in urls if u["score"] >= 10)
    se = [{"technique": t, "evidence": e, "why": TECH_WHY[t]} for t, e in techs.items()]
    sc = risk_scorer.calculate(kws, urls, se, extra)
    flags = ['Phrase "%s": %s' % (k["phrase"], k["why"]) for k in kws]
    flags += ["%s: %s" % (u["domain"], i["label"]) for u in urls for i in u["indicators"]] + [e["label"] for e in extra]
    explanation = ("The message combines several risk signals, which together make it likely unsafe." if sc["score"] >= 50 else
                   "Some signals were found; verify the sender independently." if sc["score"] >= 25 else
                   "Few or no phishing signals were found.")
    r = {"score": sc["score"], "level": sc["level"], "breakdown": sc["breakdown"], "method": sc["method"],
         "summary": rg.make_summary(sc["score"], sc["level"], kws, urls, se), "keywords": kws, "urls": urls,
         "social_engineering": se, "red_flags": flags, "explanation": explanation,
         "recommendations": rg.RECS[sc["level"]], "disclaimer": rg.DISCLAIMER,
         "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "message_length": len(text),
         "preview": " ".join(text.split())[:80]}
    r["report_text"] = rg.build_text_report(r)
    return r
