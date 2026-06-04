import math
import re

def payload_entropy(s):
    if not s:
        return 0.0
    
    s = str(s)
    
    probs = [float(s.count(c)) / len(s) for c in set(s)]

    ent = -sum(p * math.log(p, 2) for p in probs if p > 0)

    return ent

def count_sql_keywords(s):
    if not s:
        return 0
    
    s = s.upper()

    keywords = (
        "OR","AND","UNION","SELECT","DROP","DELETE",
        "INSERT","UPDATE","WHERE","LIMIT","ORDER"
    )

    return sum(k in s for k in keywords)

def count_special_chars(s):
    if not s:
        return 0
    
    return len(re.findall(r"[\'\";\-#/\*]", s))