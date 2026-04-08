/* Nmap `expr_match` excerpt from osscan.cc — Nmap Public Source License (NPSL). */
#include <cctype>
#include <cstring>

/* Lengths are always supplied by Rust (`str` is not NUL-terminated). Do not use strlen. */

static inline const char *strchr_p(const char *start, const char *end, char c) {
  while (start < end && *start != c)
    start++;
  return (start < end) ? start : nullptr;
}

static bool expr_match(const char *val, size_t vlen, const char *expr, size_t explen, bool do_nested) {
  const char *p, *q, *q1;

  if (explen == 0) {
    return vlen == 0;
  }

  p = expr;
  const char *const p_end = p + explen;

  do {
    const char *nest = NULL;
    const char *subval = val;
    size_t sublen;
    q = strchr_p(p, p_end, '|');
    nest = strchr_p(p, q ? q : p_end, '[');

    if (vlen == 0) {
      if (q == p || p == p_end) {
        return true;
      } else if (!nest) {
        goto next_expr;
      }
    }

    if (do_nested && nest) {
      while (nest) {
        q1 = strchr_p(nest, p_end, ']');
        if (!q1)
          goto next_expr;
        if (q && q < q1) {
          q = strchr_p(q1, p_end, '|');
        }
        sublen = (size_t)(nest - p);
        if (strncmp(p, subval, sublen) != 0) {
          goto next_expr;
        }
        nest++;
        subval += sublen;
        size_t nlen = 0;
        while (isxdigit((unsigned char)subval[nlen])) {
          nlen++;
        }
        p = q1 + 1;
        if (nlen > 0 && expr_match(subval, nlen, nest, (size_t)(q1 - nest), false)) {
          subval += nlen;
          nest = strchr_p(p, q ? q : p_end, '[');
        } else {
          goto next_expr;
        }
      }
      sublen = vlen - (size_t)(subval - val);
      if ((explen - (size_t)(p - expr)) == sublen && strncmp(subval, p, sublen) == 0) {
        return true;
      } else {
        goto next_expr;
      }
    }
    sublen = q ? (size_t)(q - p) : explen - (size_t)(p - expr);
    if (isxdigit((unsigned char)*subval)) {
      while (*subval == '0' && vlen > 1) {
        subval++;
        vlen--;
      }
      if (*p == '>') {
        do {
          p++;
          sublen--;
        } while (*p == '0' && sublen > 1);
        if ((vlen > sublen) || (vlen == sublen && strncmp(subval, p, vlen) > 0)) {
          return true;
        }
        goto next_expr;
      } else if (*p == '<') {
        do {
          p++;
          sublen--;
        } while (*p == '0' && sublen > 1);
        if ((vlen < sublen) || (vlen == sublen && strncmp(subval, p, vlen) < 0)) {
          return true;
        }
        goto next_expr;
      } else if (isxdigit((unsigned char)*p)) {
        while (sublen > 1 && *p == '0') {
          p++;
          sublen--;
        }
        q1 = strchr_p(p, q ? q : p_end, '-');
        if (q1 != NULL) {
          if (q1 == p) {
            p--;
            sublen++;
          }
          size_t sublen1 = (size_t)(q1 - p);
          if ((vlen > sublen1) || (vlen == sublen1 && strncmp(subval, p, vlen) >= 0)) {
            p = q1 + 1;
            sublen -= (sublen1 + 1);
            while (sublen > 1 && *p == '0') {
              p++;
              sublen--;
            }
            if ((vlen < sublen) || (vlen == sublen && strncmp(subval, p, vlen) <= 0)) {
              return true;
            }
          }
          goto next_expr;
        }
      } else {
        goto next_expr;
      }
    }
    if (vlen == sublen && strncmp(p, subval, vlen) == 0) {
      return true;
    }
  next_expr:
    if (q)
      p = q + 1;
  } while (q);

  return false;
}

extern "C" unsigned char nmap_expr_match(const char *val, size_t vlen, const char *expr, size_t explen,
                                         int do_nested_i) {
  return expr_match(val, vlen, expr, explen, do_nested_i != 0) ? 1 : 0;
}
