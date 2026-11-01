"""Phrase-based detection. Rules match whole phrases (not lone words) and
ignore matches inside a negation such as "we will never ask you to share your OTP"."""
import re

# (rule_id, category, regex, why it is suspicious, points)
RULES = [
 ("urgent_action", "Urgency & Pressure", r"immediate(ly)? action|act (now|immediately)|urgent(ly)? (verification|action|attention|response)|respond within \d+ ?(hours?|hrs?|minutes?)|within \d+ ?(hours?|hrs?|minutes?) (or|otherwise|else)", "Artificial deadlines push people to act before thinking.", 8),
 ("account_threat", "Urgency & Pressure", r"account (has been |will be |is |was )?(temporarily )?(suspended|locked|disabled|restricted|deactivated|closed)|permanent(ly)? (closure|suspension)", "Threatening loss of access is a classic pressure tactic.", 10),
 ("limited_time", "Urgency & Pressure", r"limited time|expires (today|soon|in \d+ ?\w+)|last chance|final (notice|warning)", "Scarcity language discourages verification.", 5),
 ("payment_issue", "Financial Threats", r"payment (has )?(failed|declined)|unusual (transaction|activity|sign-?in|login)|suspicious (transaction|activity|login)|refund (is )?pending|unauthori[sz]ed (transaction|access|login)", "Fake billing or fraud alerts trigger fear of financial loss.", 8),
 ("bank_blocked", "Financial Threats", r"(bank )?(account|card) (has been |is |was )?(blocked|frozen|on hold)", "Claims of a blocked account or card create panic.", 10),
 ("cred_request", "Credential Theft", r"(verify|confirm|update|validate|re-?enter) (your )?(account )?(password|login( details| credentials)?|credentials|identity|card (details|number)|bank details|account details)", "Legitimate organisations rarely ask you to confirm credentials through a message.", 15),
 ("otp_request", "Credential Theft", r"(enter|share|send|provide|tell|reply with|forward) (us )?(your |the )?(otp|one[- ]time (password|passcode|code)|pin|cvv)", "OTPs and PINs must never be shared; they authorise transactions.", 18),
 ("sensitive_info", "Credential Theft", r"(send|share|provide|submit|reply with) (us )?(your )?(bank details|aadhaar|pan (card|number)|ssn|social security|card number|passport|date of birth)", "Requests for identity or financial data enable identity theft.", 15),
 ("reward", "Reward Manipulation", r"you('ve| have) (won|been selected)|you are (selected|chosen|a winner)|claim your (prize|reward|gift|winnings)|free gift|exclusive reward|congratulations[^.!?]{0,40}(won|winner|selected)", "Unrealistic rewards are used as bait.", 15),
 ("advance_fee", "Advance-Fee Request", r"(registration|redelivery|re-?delivery|processing|training|handling|clearance|security) (fee|charge|deposit)|refundable (fee|deposit)", "Small upfront payments are used to steal card data or money.", 14),
 ("click_cta", "Call to Action", r"(click|tap) (on )?(the |this )?(link|here|below|button)|follow (the|this) link|log ?in (here|now|below)", "Pushing you to click is how the attack is delivered.", 5),
]
_COMPILED = [(r, c, re.compile(r"\b(?:" + p + r")\b", re.I), w, pts) for r, c, p, w, pts in RULES]
_NEGATION = re.compile(r"\b(never|not|don't|do not|won't|will not|no one)\s+(?:[\w']+\s+){0,3}$", re.I)


def _negated(text, start):
    """True only if a negation sits just before the phrase in the same clause,
    e.g. "never ask you to share your OTP". "Do not delay: verify your password" is NOT negated."""
    clause = re.split(r"[.!?\n:;,]", text[max(0, start - 60):start])[-1]
    return bool(_NEGATION.search(clause))


def detect_keywords(text):
    """Return one finding per rule (first non-negated match, with an occurrence count)."""
    found = []
    for rule_id, category, rx, why, points in _COMPILED:
        hits = [m for m in rx.finditer(text) if not _negated(text, m.start())]
        if hits:
            found.append({"rule_id": rule_id, "phrase": hits[0].group(0), "category": category,
                          "why": why, "points": points, "count": len(hits)})
    return found
