def calculate_risk(ml_score: float | None, nlp_score: float | None, cv_score: float | None, whitelisted: bool = False):
    if whitelisted:
        return {
            "risk_score": 0.0,
            "verdict": "ALLOW",
            "action": "allow",
            "reason": "trusted_sender_whitelist"
        }

    ml = ml_score or 0.0
    nlp = nlp_score or 0.0
    cv = cv_score or 0.0

    risk_score = (
        0.5 * ml +
        0.3 * nlp +
        0.2 * cv
    )

    if risk_score >= 0.6:
        verdict = "BLOCK"
        action = "block"
    elif risk_score >= 0.3:
        verdict = "FLAG"
        action = "flag"
    else:
        verdict = "ALLOW"
        action = "allow"

    return {
        "risk_score": round(risk_score, 2),
        "verdict": verdict,
        "action": action,
        "reason": "score_threshold"
    }
