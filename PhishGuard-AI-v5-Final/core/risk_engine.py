def calculate_risk(evidence, ml_probability, domain_age=None, official=False, threat_hit=False):
    rule_points=max(0,sum(max(0,e.get("points",0)) for e in evidence))
    rule_score=min(100,rule_points*2.2)
    score=rule_score*0.55 + float(ml_probability)*0.25 + (25 if threat_hit else 0)
    if official: score=max(0,score-35)
    if domain_age is not None and domain_age>3650: score=max(0,score-8)
    score=round(min(100,max(0,score)),1)
    if official and score<60: verdict="LEGITIMATE / OFFICIAL DOMAIN"
    elif score>=70: verdict="PHISHING / HIGH RISK"
    elif score>=35: verdict="SUSPICIOUS"
    else: verdict="LOW RISK / NO STRONG SIGNAL"
    return score,verdict
