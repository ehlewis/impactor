
def score(evidence_count:int)->float:
    return min(1.0, evidence_count/10)
