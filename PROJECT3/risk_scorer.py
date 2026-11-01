"""Transparent scoring: every point in the total appears in the breakdown."""
CATEGORY_CAP = 30   # per keyword category, prevents one theme dominating
URL_CAP = 40        # per URL
BONUS_PER_TECHNIQUE, BONUS_CAP = 3, 12
LEVELS = [(75, "Critical Risk"), (50, "High Risk"), (25, "Moderate Risk"), (0, "Low Risk")]


def classify(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name


def calculate(keywords, urls, techniques, extra=()):
    breakdown, used = [], {}
    for k in keywords:  # each rule already counted once (no double counting)
        pts = max(0, min(k["points"], CATEGORY_CAP - used.get(k["category"], 0)))
        used[k["category"]] = used.get(k["category"], 0) + pts
        if pts:
            breakdown.append({"source": "Keyword", "label": '"%s" (%s)' % (k["phrase"], k["category"]), "points": pts})
    for i, u in enumerate(sorted(urls, key=lambda u: -u["score"])):
        pts = min(u["score"], URL_CAP) // (1 if i == 0 else 2)  # extra links count half
        if pts:
            breakdown.append({"source": "URL", "label": u["domain"], "points": pts})
    breakdown.extend(extra)
    bonus = min(BONUS_CAP, max(0, len(techniques) - 1) * BONUS_PER_TECHNIQUE)
    if bonus:
        breakdown.append({"source": "Combination", "label": "%d distinct manipulation techniques" % len(techniques), "points": bonus})
    score = min(100, sum(b["points"] for b in breakdown))
    method = ["Each phrase rule counts once; each keyword category is capped at %d." % CATEGORY_CAP,
              "Each URL is capped at %d; additional URLs count half." % URL_CAP,
              "+%d per extra distinct social-engineering technique (max %d)." % (BONUS_PER_TECHNIQUE, BONUS_CAP),
              "Total is capped at 100. Bands: 0-24 Low, 25-49 Moderate, 50-74 High, 75-100 Critical."]
    return {"score": score, "level": classify(score), "breakdown": breakdown, "method": method}
