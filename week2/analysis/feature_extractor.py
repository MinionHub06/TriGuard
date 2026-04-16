import re
import math
import itertools
import sqlparse
from collections import Counter


# ── Section 4a: Shannon Entropy ─────────────────────────────────────
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


# ── Section 4b: AST Feature Extractor ───────────────────────────────
def extract_ast_features(query: str) -> dict:
    feats = {
        'ast_token_count':      0,
        'ast_keyword_count':    0,
        'ast_has_where':        0,
        'ast_has_comparison':   0,
        'ast_has_union':        0,
        'ast_subquery_depth':   0,
        'ast_identifier_count': 0,
    }
    try:
        parsed = sqlparse.parse(query)
        if not parsed:
            return feats

        def traverse(token, depth=0):
            feats['ast_token_count'] += 1
            ttype = token.ttype
            tval  = str(token).upper().strip()

            if ttype in (sqlparse.tokens.Keyword,
                         sqlparse.tokens.Keyword.DML,
                         sqlparse.tokens.Keyword.DDL):
                feats['ast_keyword_count'] += 1
                if tval == 'WHERE': feats['ast_has_where'] = 1
                if tval == 'UNION': feats['ast_has_union'] = 1

            if isinstance(token, sqlparse.sql.Where):       feats['ast_has_where'] = 1
            if isinstance(token, sqlparse.sql.Comparison):  feats['ast_has_comparison'] = 1
            if isinstance(token, sqlparse.sql.Identifier):  feats['ast_identifier_count'] += 1
            if isinstance(token, sqlparse.sql.Parenthesis):
                feats['ast_subquery_depth'] = max(feats['ast_subquery_depth'], depth)

            if hasattr(token, 'tokens'):
                for child in token.tokens:
                    traverse(child, depth + 1)

        for stmt in parsed:
            traverse(stmt)

    except Exception:
        pass

    return feats


# ── Section 4c: Full 25-Feature Extractor ───────────────────────────
HIGH_LIFT_KEYWORDS = [
    'UNION', 'SELECT', 'INSERT', 'DROP', 'EXEC', 'EXECUTE',
    'SLEEP', 'WAITFOR', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML',
    'INFORMATION_SCHEMA', 'XP_CMDSHELL', 'LOAD_FILE', 'OUTFILE',
]

COMMENT_PATTERNS = [r'--', r'/\*.*?\*/', r'#', r';--', r'/*!']


def extract_features(query: str) -> dict:
    q       = str(query)
    q_upper = q.upper()
    q_len   = max(len(q), 1)

    # LEXICAL (8)
    feat_length            = len(q)
    feat_entropy           = shannon_entropy(q)
    special                = set(r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~""")
    feat_special_char_ratio = sum(1 for c in q if c in special) / q_len
    feat_digit_ratio       = sum(1 for c in q if c.isdigit()) / q_len
    feat_alpha_ratio       = sum(1 for c in q if c.isalpha()) / q_len
    feat_whitespace_count  = sum(1 for c in q if c in ' \t\n\r\x0b\x0c')
    feat_max_run           = max((len(list(g)) for _, g in itertools.groupby(q)), default=0)
    feat_hex_encoded       = int(
        bool(re.search(r'0x[0-9a-fA-F]{2}', q)) or
        bool(re.search(r'%[0-9a-fA-F]{2}', q))
    )

    # KEYWORD (7)
    feat_keyword_count     = sum(
        len(re.findall(rf'\b{re.escape(kw)}\b', q_upper))
        for kw in HIGH_LIFT_KEYWORDS
    )
    feat_keyword_diversity = sum(
        1 for kw in HIGH_LIFT_KEYWORDS
        if re.search(rf'\b{re.escape(kw)}\b', q_upper)
    )
    feat_has_union         = int(bool(re.search(r'\bUNION\b', q_upper)))
    feat_boolean_op_count  = len(re.findall(r'\b(OR|AND)\b', q_upper))
    feat_has_time_keyword  = int(bool(re.search(r'\b(SLEEP|WAITFOR|BENCHMARK)\b', q_upper)))
    feat_has_exfil_keyword = int(bool(re.search(r'\b(OUTFILE|DUMPFILE|LOAD_FILE)\b', q_upper)))
    feat_has_destructive   = int(bool(re.search(r'\b(DROP|TRUNCATE|DELETE|UPDATE|INSERT)\b', q_upper)))

    # STRUCTURAL (5)
    feat_comment_count     = sum(len(re.findall(p, q, re.DOTALL)) for p in COMMENT_PATTERNS)
    feat_quote_imbalance   = q.count("'") % 2
    feat_comparison_count  = len(re.findall(r'[<>!=]=?', q))
    feat_semicolon_count   = q.count(';')
    url_enc                = len(re.findall(r'%[0-9a-fA-F]{2}', q))
    double_enc             = len(re.findall(r'%25[0-9a-fA-F]{2}', q))
    feat_url_encoding_depth = url_enc + double_enc * 2

    # AST-DERIVED (5)
    ast = extract_ast_features(q)

    return {
        'length':             feat_length,
        'entropy':            feat_entropy,
        'special_char_ratio': feat_special_char_ratio,
        'digit_ratio':        feat_digit_ratio,
        'alpha_ratio':        feat_alpha_ratio,
        'whitespace_count':   feat_whitespace_count,
        'max_char_run':       feat_max_run,
        'hex_encoded':        feat_hex_encoded,
        'keyword_count':      feat_keyword_count,
        'keyword_diversity':  feat_keyword_diversity,
        'has_union':          feat_has_union,
        'boolean_op_count':   feat_boolean_op_count,
        'has_time_keyword':   feat_has_time_keyword,
        'has_exfil_keyword':  feat_has_exfil_keyword,
        'has_destructive':    feat_has_destructive,
        'comment_count':      feat_comment_count,
        'quote_imbalance':    feat_quote_imbalance,
        'comparison_count':   feat_comparison_count,
        'semicolon_count':    feat_semicolon_count,
        'url_encoding_depth': feat_url_encoding_depth,
        'ast_token_count':    ast['ast_token_count'],
        'ast_keyword_count':  ast['ast_keyword_count'],
        'ast_has_where':      ast['ast_has_where'],
        'ast_has_comparison': ast['ast_has_comparison'],
        'ast_has_union':      ast['ast_has_union'],
    }