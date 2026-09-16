from parser import load_alerts
from collections import defaultdict
from ml_model import evaluate as ml_evaluate

ip_offense_count = defaultdict(int)

SEVERITY_THRESHOLD = 2   # severity 1 or 2 (out of 1-3) triggers a block
REPEAT_OFFENSE_LIMIT = 5  # matches the SSH brute-force rule's own 5-attempt
                          # threshold. Deliberately not left at 2: with a
                          # limit that low, this rule alone would block any
                          # repeating source by its 2nd alert, before the ML
                          # layer's activity tracker ever accumulates enough
                          # history to make an informed call — effectively
                          # making the ML layer dead weight for anything
                          # that repeats. Raising it gives ML a real window
                          # (alerts 2-4) to catch and confirm attacks earlier
                          # than the fixed rule would on its own, which is
                          # the actual point of adding it.


def should_block(alert):
    """Decide whether an alert's source IP should be blocked.

    Decision order:
      1. Existing rule-based checks (severity threshold, repeat-offense
         count) — fast, deterministic, and unchanged from the original
         design. If either fires, we block immediately without involving
         the ML layer at all.
      2. Only if neither rule-based check fires (i.e. the alert would
         otherwise be silently allowed), consult the local ML layer:
         an Isolation Forest flags behaviourally anomalous traffic
         (e.g. a slow/wide port scan that never trips the fixed severity
         or repeat-offense thresholds), and a classifier validates that
         flag before it's allowed to trigger a block on its own — this
         keeps the ML layer as a supplementary safety net that catches
         what the fixed thresholds miss, rather than a replacement for
         them, and reduces false positives from acting on the anomaly
         score alone.
    """
    ip_offense_count[alert["source_ip"]] += 1

    # Always run this IP's alert through the ML layer, even if the rules
    # below are about to block it anyway. This isn't wasted work: it's
    # what keeps the activity tracker's frequency/port-diversity history
    # for this IP up to date. If we only called this when the fixed rules
    # DIDN'T already trigger, a repeat offender would get blocked on its
    # 2nd alert (REPEAT_OFFENSE_LIMIT) before the tracker ever recorded a
    # 2nd data point — freezing its behavioural signal at "1 event" forever
    # and making the ML layer blind to exactly the pattern it exists to catch.
    is_anomalous, is_validated, ml_detail = ml_evaluate(
        alert, ip_offense_count[alert["source_ip"]]
    )

    if alert["severity"] <= SEVERITY_THRESHOLD:  # note: <= now (lower = worse)
        return True, "high severity"

    if ip_offense_count[alert["source_ip"]] >= REPEAT_OFFENSE_LIMIT:
        return True, "repeated offender"

    # Below both fixed thresholds — this is where the ML layer's verdict
    # actually gets to influence the outcome: catching anomalous behaviour
    # (e.g. a slow/wide scan) that never trips severity or repeat-offense
    # limits on its own.
    if is_anomalous and is_validated:
        return True, f"ml anomaly detected ({ml_detail})"

    if is_anomalous and not is_validated:
        # Isolation Forest flagged it, but the classifier wasn't confident
        # enough to treat it as a real attack pattern — logged for
        # visibility but NOT blocked, to keep false positives low.
        return False, f"ml flagged but not validated, allowing ({ml_detail})"

    return False, "below threshold"


if __name__ == "__main__":
    alerts = load_alerts("sample_alerts.json")
    for alert in alerts:
        block, reason = should_block(alert)
        status = "BLOCK" if block else "allow"
        print(f"{status:6} | {alert['source_ip']:15} | severity={alert['severity']:3} | {reason} | {alert['description']}")