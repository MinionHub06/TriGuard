import re
import sqlparse


class ASTLayer:
    DANGER_TOKENS = {
        "UNION", "SELECT", "DROP", "INSERT", "DELETE", "UPDATE",
        "EXEC", "EXECUTE", "SLEEP", "WAITFOR", "BENCHMARK",
        "EXTRACTVALUE", "UPDATEXML", "XP_CMDSHELL", "OUTFILE",
    }

    def score(self, query: str) -> float:
        """
        Parse query with sqlparse and return a structural risk score 0.0-1.0.

        Components:
          - danger token density  (50% weight)
          - comment patterns      (20% weight)
          - UNION keyword         (20% weight)
          - subquery nesting      (10% weight)
        """
        try:
            parsed = sqlparse.parse(query)
            if not parsed:
                return 0.0

            danger_hits  = 0
            total_tokens = 0
            has_subquery = 0

            def traverse(token, depth=0):
                nonlocal danger_hits, total_tokens, has_subquery
                total_tokens += 1
                tval = str(token).upper().strip()
                if tval in self.DANGER_TOKENS:
                    danger_hits += 1
                if isinstance(token, sqlparse.sql.Parenthesis) and depth > 0:
                    has_subquery = 1
                if hasattr(token, 'tokens'):
                    for child in token.tokens:
                        traverse(child, depth + 1)

            for stmt in parsed:
                traverse(stmt)

            has_comment = 1 if re.search(r'--|/\*|#|;--', query) else 0
            has_union   = 1 if re.search(r'\bUNION\b', query, re.IGNORECASE) else 0

            token_density = (danger_hits / max(total_tokens, 1))

            raw_score = (
                token_density  * 0.50 +
                has_comment    * 0.20 +
                has_union      * 0.20 +
                has_subquery   * 0.10
            )

            return round(min(raw_score, 1.0), 4)

        except Exception:
            return 0.0