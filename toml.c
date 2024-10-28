#define _POSIX_C_SOURCE 200809L // strnlen

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "toml.h"

static void *toml_calloc(size_t nmemb, size_t sz);
static char *toml_strdup(const char *s);
static char *toml_strndup(const char *s, size_t n);
static void xfree(const void *x);
static int next_token(toml_context *ctx, bool dotisspecial);
static int e_outofmemory(toml_context *ctx, const char *fline);
static int e_internal(toml_context *ctx, const char *fline);
static int e_syntax(toml_context *ctx, int lineno, const char *msg);
static int e_badkey(toml_context *ctx, int lineno);
static int e_keyexists(toml_context *ctx, int lineno);
static int e_forbid(toml_context *ctx, int lineno, const char *msg);
static void *expand(void *p, int sz, int newsz);
static void **expand_ptrarr(void **p, int n);
static toml_arritem *expand_arritem(toml_arritem *p, int n); 
static char *norm_lit_str(const char *src, int srclen, int *len, bool multiline, bool is_key, char *errbuf, int errbufsz);
static char *norm_basic_str(const char *src, int srclen, int *len, bool multiline, bool is_key, char *errbuf, int errbufsz);
static char *normalize_key(toml_context *ctx, toml_token strtokk, int *keylen);
static int check_key(toml_table *tab, const char *key, toml_keyval **ret_val, toml_array **ret_arr, toml_table **ret_tab);
static int key_kind(toml_table *tab, const char *key);
static toml_keyval *create_keyval_in_table(toml_context *ctx, toml_table *tab, toml_token keytok);
static toml_table *create_keytable_in_table(toml_context *ctx, toml_table *tab, toml_token keytok); 
static toml_array *create_keyarray_in_table(toml_context *ctx, toml_table *tab, toml_token keytok, char kind);
static toml_arritem *create_value_in_array(toml_context *ctx, toml_array *parent);
static toml_array *create_array_in_array(toml_context *ctx, toml_array *parent);
static toml_table *create_table_in_array(toml_context *ctx, toml_array *parent);
static int skip_newlines(toml_context *ctx, bool isdotspecial);
static int parse_keyval(toml_context *ctx, toml_table *tab);
static inline int eat_token(toml_context *ctx, TomlTokenType typ, bool isdotspecial, const char *fline);
static int parse_inline_table(toml_context *ctx, toml_table *tab);
static int valtype(const char *val);
static int parse_array(toml_context *ctx, toml_array *arr);
static int fill_tabpath(toml_context *ctx);
static int walk_tabpath(toml_context *ctx);
static int parse_select(toml_context *ctx);
static void xfree_kval(toml_keyval *p);
static void xfree_arr(toml_array *p);
static void set_token(toml_context *ctx, TomlTokenType tok, int lineno, char *ptr, int len);
static void set_eof(toml_context *ctx, int lineno);
static int scan_string(toml_context *ctx, char *p, int lineno, bool dotisspecial); 
static int next_token(toml_context *ctx, bool dotisspecial); 
static int read_unicode_escape(int64_t code, char buf[6]);

typedef const char *toml_unparsed;

toml_unparsed toml_table_unparsed  (const toml_table *table, const char *key);
toml_unparsed toml_array_unparsed  (const toml_array *array, int idx);
bool           toml_value_string    (toml_unparsed s, char **ret, int *len);
bool           toml_value_bool      (toml_unparsed s, bool *ret);
bool           toml_value_int       (toml_unparsed s, int64_t *ret);
bool           toml_value_double    (toml_unparsed s, double *ret);

#define TOSTRING(x) #x
#define FLINE __FILE__ ":" TOSTRING(__LINE__)

static uint8_t const u8_length[] = {1,1,1,1,1,1,1,1,0,0,0,0,2,2,3,4};
#define u8length(s) u8_length[(((uint8_t *)(s))[0] & 0xFF) >> 4];

// Redefinition of calloc
void *toml_calloc(size_t nmemb, size_t sz) {
    #define ALIGN8(sz) (((sz) + 7) & ~7)
    const unsigned int nb = ALIGN8(sz) * nmemb;
    void *p = malloc(nb);
    if (p) {
        memset(p, 0, nb);
    }
    return p;
}

char *toml_strdup(const char *s) {
    const unsigned int len = strlen(s);
    char *p = malloc(len + 1);
    if (p) {
        memcpy(p, s, len);
        p[len] = 0;
    }
    return p;
}

// Redefinition of strndup
char *toml_strndup(const char *s, size_t n) {
    const size_t len = strnlen(s, n);
    char *p = malloc(len + 1);
    if (p) {
        memcpy(p, s, len);
        p[len] = 0;
    }
    return p;
}

void xfree(const void *x) {
    if (x) {
        free((void *)(intptr_t)x);
    }
}

void xfree_kval(toml_keyval *p) {
    if (!p) {
        return;
    }
    xfree(p->key);
    xfree(p->val);
    xfree(p);
}

void xfree_arr(toml_array *p) {
    if (!p) {
        return;
    }

    xfree(p->key);
    const int n = p->nitem;
    for (int i = 0; i < n; i++) {
        toml_arritem *a = &p->item[i];
        if (a->val) {
            xfree(a->val);
        } else if (a->arr) {
            xfree_arr(a->arr);
        } else if (a->tab) {
            toml_table_free(a->tab);
        }
    }
    xfree(p->item);
    xfree(p);
}

/* Convert escape to UTF-8. Returns bytes used in buf to encode the char, or -1 on error.
* http://stackoverflow.com/questions/6240055/manually-converting-unicode-codepoints-into-utf-8-and-utf-16 */
int read_unicode_escape(int64_t code, char buf[6]) {
    if (0xd800 <= code && code <= 0xdfff) { // UTF-16 surrogates
        return -1;
    }
    if (0x10FFFF < code || code < 0) {
        return -1;
    }
    if (code <= 0x7F) { // 0x00000000 - 0x0000007F: 0xxxxxxx
        buf[0] = (unsigned char)code;
        return 1;
    }
    if (code <= 0x000007FF) { // 0x00000080 - 0x000007FF: 110xxxxx 10xxxxxx
        buf[0] = (unsigned char)(0xc0 | (code >> 6));
        buf[1] = (unsigned char)(0x80 | (code & 0x3f));
        return 2;
    }
    if (code <= 0x0000FFFF) { // 0x00000800 - 0x0000FFFF: 1110xxxx 10xxxxxx 10xxxxxx
        buf[0] = (unsigned char)(0xe0 | (code >> 12));
        buf[1] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
        buf[2] = (unsigned char)(0x80 | (code & 0x3f));
        return 3;
    }
    if (code <= 0x001FFFFF) { // 0x00010000 - 0x001FFFFF: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        buf[0] = (unsigned char)(0xf0 | (code >> 18));
        buf[1] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
        buf[2] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
        buf[3] = (unsigned char)(0x80 | (code & 0x3f));
        return 4;
    }
    if (code <= 0x03FFFFFF) { // 0x00200000 - 0x03FFFFFF: 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        buf[0] = (unsigned char)(0xf8 | (code >> 24));
        buf[1] = (unsigned char)(0x80 | ((code >> 18) & 0x3f));
        buf[2] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
        buf[3] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
        buf[4] = (unsigned char)(0x80 | (code & 0x3f));
        return 5;
    }
    if (code <= 0x7FFFFFFF) { // 0x04000000 - 0x7FFFFFFF: 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
        buf[0] = (unsigned char)(0xfc | (code >> 30));
        buf[1] = (unsigned char)(0x80 | ((code >> 24) & 0x3f));
        buf[2] = (unsigned char)(0x80 | ((code >> 18) & 0x3f));
        buf[3] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
        buf[4] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
        buf[5] = (unsigned char)(0x80 | (code & 0x3f));
        return 6;
    }
    return -1;
}


int e_outofmemory(toml_context *ctx, const char *fline) {
    snprintf(ctx->errbuf, ctx->errbufsz, "out of memory (%s)", fline);
    return -1;
}

int e_internal(toml_context *ctx, const char *fline) {
    snprintf(ctx->errbuf, ctx->errbufsz, "internal error (%s)", fline);
    return -1;
}

int e_syntax(toml_context *ctx, int lineno, const char *msg) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: %s", lineno, msg);
    return -1;
}

int e_badkey(toml_context *ctx, int lineno) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: bad key", lineno);
    return -1;
}

int e_keyexists(toml_context *ctx, int lineno) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: key exists", lineno);
    return -1;
}

int e_forbid(toml_context *ctx, int lineno, const char *msg) {
    snprintf(ctx->errbuf, ctx->errbufsz, "line %d: %s", lineno, msg);
    return -1;
}

void *expand(void *p, int sz, int newsz) {
    void *s = malloc(newsz);
    if (!s) {
        return 0;
    }

    if (p) {
        memcpy(s, p, sz);
        free(p);
    }
    return s;
}

void **expand_ptrarr(void **p, int n) {
    void **s = malloc((n + 1) * sizeof(void *));
    if (!s) {
        return 0;
    }

    s[n] = 0;
    if (p) {
        memcpy(s, p, n * sizeof(void *));
        free(p);
    }
    return s;
}

toml_arritem *expand_arritem(toml_arritem *p, int n) {
    toml_arritem *pp = (toml_arritem *) expand(p, n * sizeof(*p), (n + 1) * sizeof(*p));
    if (!pp) {
        return 0;
    }
    memset(&pp[n], 0, sizeof(pp[n]));
    return pp;
}

char *norm_lit_str(const char *src, int srclen, int *len, bool multiline, bool is_key, char *errbuf, int errbufsz) {
    const char *sp  = src;
    const char *sq  = src + srclen;
    char *dst = 0; // will write to dst[] and return it
    int max  = 0; // max size of dst[]
    int off  = 0; // cur offset in dst[]

    for (;;) { // scan forward on src
        if (off >= max - 10) { // have some slack for misc stuff
            int newmax = max + 50;
            char *x = (char *)expand(dst, max, newmax);
            if (!x) {
                xfree(dst);
                snprintf(errbuf, errbufsz, "out of memory");
                return 0;
            }
            dst = x;
            max = newmax;
        }

        if (sp >= sq) { // finished?
            break;
        }

        uint8_t l = u8length(sp);
        if (l == 0) {
            xfree(dst);
            snprintf(errbuf, errbufsz, "invalid UTF-8 at byte pos %d", off);
            return 0;
        }
        if (l > 1) {
            for (int i = 0; i < l; i++) {
                char ch = *sp++;
                if ((ch & 0x80) != 0x80) {
                    xfree(dst);
                    snprintf(errbuf, errbufsz, "invalid UTF-8 at byte pos %d", off);
                    return 0;
                }
                dst[off++] = ch;
            }
            continue;
        }

        char ch = *sp++;
        if (is_key && ch == '\n') {
            xfree(dst);
            snprintf(errbuf, errbufsz, "literal newlines not allowed in key");
            return 0;
        }
        // control characters other than tab is not allowed
        if ((0 <= ch && ch <= 0x08) || (0x0a <= ch && ch <= 0x1f) || ch == 0x7f) {
            if (!(multiline && (ch == '\r' || ch == '\n'))) {
                xfree(dst);
                snprintf(errbuf, errbufsz, "invalid char U+%04x", ch);
                return 0;
            }
        }
        dst[off++] = ch; // a plain copy suffice
    }
    *len = off;
    dst[off++] = 0;
    return dst;
}


/* Convert src to raw unescaped utf-8 string.
 * Returns NULL if error with errmsg in errbuf. */
char *norm_basic_str(const char *src, int srclen, int *len, bool multiline, bool is_key, char *errbuf, int errbufsz) {
    const char *sp  = src;
    const char *sq  = src + srclen;
    char *dst = 0; // will write to dst[] and return it
    int max  = 0; // max size of dst[]
    int off  = 0; // cur offset in dst[]
    // scan forward on src
    for (;;) {
        if (off >= max - 10) { // have some slack for misc stuff
            int newmax = max + 50;
            char *x = (char *) expand(dst, max, newmax);
            if (!x) {
                xfree(dst);
                snprintf(errbuf, errbufsz, "out of memory");
                return 0;
            }
            dst = x;
            max = newmax;
        }

        if (sp >= sq) { // finished?
            break;
        }

        uint8_t l = u8length(sp);
        if (l == 0) {
            xfree(dst);
            snprintf(errbuf, errbufsz, "invalid UTF-8 at byte pos %d", off);
            return 0;
        }
        if (l > 1) {
            for (int i = 0; i < l; i++) {
                char ch = *sp++;
                if ((ch & 0x80) != 0x80) {
                    xfree(dst);
                    snprintf(errbuf, errbufsz, "invalid UTF-8 at byte pos %d", off);
                    return 0;
                }
                dst[off++] = ch;
            }
            continue;
        }

        char ch = *sp++;
        if (is_key && ch == '\n') {
            xfree(dst);
            snprintf(errbuf, errbufsz, "literal newlines not allowed in key");
            return 0;
        }
        if (ch != '\\') {
            // must be escaped: U+0000 to U+0008, U+000A to U+001F, U+007F
            if ((ch >= 0 && ch <= 0x08) || (ch >= 0x0a && ch <= 0x1f) || ch == 0x7f) {
                if (!(multiline && (ch == '\r' || ch == '\n'))) {
                    xfree(dst);
                    snprintf(errbuf, errbufsz, "invalid char U+%04x", ch);
                    return 0;
                }
            }
            dst[off++] = ch; // a plain copy suffice
            continue;
        }

        if (sp >= sq) { // ch was backslash. we expect the escape char.
            snprintf(errbuf, errbufsz, "last backslash is invalid");
            xfree(dst);
            return 0;
        }

        if (multiline) {
            // for multi-line, we want to kill line-ending-backslash.
            if (sp[strspn(sp, " \t\r")] == '\n') { // if there is only whitespace after the backslash ...
                sp += strspn(sp, " \t\r\n"); // skip all the following whitespaces
                continue;
            }
        }

        ch = *sp++; // get the escaped char
        switch (ch) {
            case 'u':
            case 'U': {
                int64_t ucs = 0;
                int nhex = (ch == 'u' ? 4 : 8);
                for (int i = 0; i < nhex; i++) {
                    if (sp >= sq) {
                        snprintf(errbuf, errbufsz, "\\%c expects %d hex chars", ch, nhex);
                        xfree(dst);
                        return 0;
                    }
                    ch = *sp++;
                    int v = -1;
                    if ('0' <= ch && ch <= '9') {
                        v = ch - '0';
                    } else if ('A' <= ch && ch <= 'F') {
                        v = ch - 'A' + 10;
                    } else if ('a' <= ch && ch <= 'f') {
                        v = (ch ^ 0x20) - 'A' + 10;
                    }
                    if (v == -1) {
                        snprintf(errbuf, errbufsz, "invalid hex chars for \\u or \\U");
                        xfree(dst);
                        return 0;
                    }
                    ucs = ucs * 16 + v;
                }
                int n = read_unicode_escape(ucs, &dst[off]);
                if (n == -1) {
                    snprintf(errbuf, errbufsz, "illegal ucs code in \\u or \\U");
                    xfree(dst);
                    return 0;
                }
                off += n;
            }; continue;
            case 'b':  ch = '\b';  break;
            case 't':  ch = '\t';  break;
            case 'n':  ch = '\n';  break;
            case 'f':  ch = '\f';  break;
            case 'r':  ch = '\r';  break;
            case '"':  ch = '"';   break;
            case '\\': ch = '\\'; break;
            default:
                snprintf(errbuf, errbufsz, "illegal escape char \\%c", ch);
                xfree(dst);
                return 0;
        }
        dst[off++] = ch;
    }

    *len = off;
    dst[off++] = 0; // Cap with NUL and return it.
    return dst;
}

// Normalize a key. Convert all special chars to raw unescaped utf-8 chars.
char *normalize_key(toml_context *ctx, toml_token strtokk, int *keylen) {
    const char *sp    = strtokk.ptr;
    const char *sq    = strtokk.ptr + strtokk.len;
    int lineno = strtokk.lineno;
    int ch = *sp;
    char *ret = NULL;

    // Quoted string
    if (ch == '\'' || ch == '\"') {
        // if ''' or """, take 3 chars off front and back. Else, take 1 char off.
        bool multiline = (sp[1] == ch && sp[2] == ch);
        if (multiline) {
            sp += 3, sq -= 3;
        } else {
            sp++, sq--;
        }

        char ebuf[80];
        if (ch == '\'') {
            ret = norm_lit_str(sp, sq - sp, keylen, multiline, true, ebuf, sizeof(ebuf));
        } else {
            ret = norm_basic_str(sp, sq - sp, keylen, multiline, true, ebuf, sizeof(ebuf));
        }
        if (!ret) {
            e_syntax(ctx, lineno, ebuf);
            return 0;
        }
        return ret;
    }

    *keylen = 0;
    for (const char *c = sp; c != sq; c++) { // Bare key: allow: [A-Za-z0-9_-]+
        *keylen = *keylen + 1;
        if (isalnum(*c) || *c == '_' || *c == '-') {
            continue;
        }
        e_badkey(ctx, lineno);
        return 0;
    }

    if (!(ret = toml_strndup(sp, sq - sp))) { // dup and return
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    return ret;
}

/* Look up key in tab. Return 0 if not found, or
 * 'v'alue, 'a'rray or 't'able depending on the element. */
int check_key(toml_table *tab, const char *key, toml_keyval **ret_val, toml_array **ret_arr, toml_table **ret_tab) {
    int i;
    void *dummy;

    if (!ret_tab) {
        ret_tab = (toml_table **)&dummy;
    } 
    if (!ret_arr) {
        ret_arr = (toml_array **)&dummy;
    }
    if (!ret_val) {
        ret_val = (toml_keyval **)&dummy;
    }
    *ret_tab = 0;
    *ret_arr = 0;
    *ret_val = 0;

    for (i = 0; i < tab->nkval; i++) {
        if (strcmp(key, tab->kval[i]->key) == 0) {
            *ret_val = tab->kval[i];
            return 'v';
        }
    }
    for (i = 0; i < tab->narr; i++) {
        if (strcmp(key, tab->arr[i]->key) == 0) {
            *ret_arr = tab->arr[i];
            return 'a';
        }
    }
    for (i = 0; i < tab->ntab; i++) {
        if (strcmp(key, tab->tab[i]->key) == 0) {
            *ret_tab = tab->tab[i];
            return 't';
        }
    }
    return 0;
}

int key_kind(toml_table *tab, const char *key) {
    return check_key(tab, key, 0, 0, 0);
}

/* Create a keyval in the table. */
toml_keyval *create_keyval_in_table(toml_context *ctx, toml_table *tab, toml_token keytok) {
    int keylen;
    char *newkey = normalize_key(ctx, keytok, &keylen);
    if (!newkey) {
        return NULL;
    }

    toml_keyval *dest = 0;
    if (key_kind(tab, newkey)) {
        xfree(newkey);
        e_keyexists(ctx, keytok.lineno);
        return NULL;
    }

    const int n = tab->nkval;
    toml_keyval **base;
    if ((base = (toml_keyval **)expand_ptrarr((void **)tab->kval, n)) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }
    tab->kval = base;

    if ((base[n] = (toml_keyval *)toml_calloc(1, sizeof(*base[n]))) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }

    dest = tab->kval[tab->nkval++];
    dest->key = newkey;
    dest->keylen = keylen;
    return dest;
}


// Create a table in the table.
toml_table *create_keytable_in_table(toml_context *ctx, toml_table *tab, toml_token keytok) {
    int keylen;
    char *newkey = normalize_key(ctx, keytok, &keylen);
    if (!newkey) {
        return NULL;
    }

    toml_table *dest = 0;
    if (check_key(tab, newkey, 0, 0, &dest)) {
        xfree(newkey);

        // Special case: make explicit if table exists and was created implicitly.
        if (dest && dest->implicit) {
            dest->implicit = false;
            return dest;
        }
        e_keyexists(ctx, keytok.lineno);
        return NULL;
    }

    int n = tab->ntab;
    toml_table **base;
    if ((base = (toml_table **)expand_ptrarr((void **)tab->tab, n)) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }
    tab->tab = base;

    if ((base[n] = (toml_table *)toml_calloc(1, sizeof(*base[n]))) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }

    dest = tab->tab[tab->ntab++];
    dest->key = newkey;
    dest->keylen = keylen;
    return dest;
}

// Create an array in the table.
toml_array *create_keyarray_in_table(toml_context *ctx, toml_table *tab, toml_token keytok, char kind) {
    int keylen;
    char *newkey = normalize_key(ctx, keytok, &keylen);
    if (!newkey) {
        return NULL;
    } 
    if (key_kind(tab, newkey)) {
        xfree(newkey);
        e_keyexists(ctx, keytok.lineno);
        return NULL;
    }

    int n = tab->narr;
    toml_array **base;
    if ((base = (toml_array **)expand_ptrarr((void **)tab->arr, n)) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }
    tab->arr = base;

    if ((base[n] = (toml_array *)toml_calloc(1, sizeof(*base[n]))) == 0) {
        xfree(newkey);
        e_outofmemory(ctx, FLINE);
        return NULL;
    }
    toml_array *dest = tab->arr[tab->narr++];

    dest->keylen = keylen;
    dest->key = newkey;
    dest->kind = kind;
    return dest;
}

toml_arritem *create_value_in_array(toml_context *ctx, toml_array *parent) {
    const int n = parent->nitem;
    toml_arritem *base = expand_arritem(parent->item, n);
    if (!base) {
        e_outofmemory(ctx, FLINE);
        return NULL;
    }
    parent->item = base;
    parent->nitem++;
    return &parent->item[n];
}

/* Create an array in an array */
toml_array *create_array_in_array(toml_context *ctx, toml_array *parent) {
    const int n = parent->nitem;
    toml_arritem *base = expand_arritem(parent->item, n);
    if (!base) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    toml_array *ret = (toml_array *)toml_calloc(1, sizeof(toml_array));
    if (!ret) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    base[n].arr = ret;
    parent->item = base;
    parent->nitem++;
    return ret;
}

/* Create a table in an array */
toml_table *create_table_in_array(toml_context *ctx, toml_array *parent) {
    int n = parent->nitem;
    toml_arritem *base = expand_arritem(parent->item, n);
    if (!base) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    toml_table *ret = (toml_table *)toml_calloc(1, sizeof(toml_table));
    if (!ret) {
        e_outofmemory(ctx, FLINE);
        return 0;
    }
    base[n].tab = ret;
    parent->item = base;
    parent->nitem++;
    return ret;
}

int skip_newlines(toml_context *ctx, bool isdotspecial) {
    while (ctx->tok.tok == NEWLINE) {
        if (next_token(ctx, isdotspecial)) {
            return -1;
        }
        if (ctx->tok.eof) {
            break;
        }
    }
    return 0;
}

inline int eat_token(toml_context *ctx, TomlTokenType typ, bool isdotspecial, const char *fline) {
    if (ctx->tok.tok != typ) {
        return e_internal(ctx, fline);
    }
    if (next_token(ctx, isdotspecial)) {
        return -1;
    }
    return 0;
}

/* We are at '{ ... }'; parse the table. */
int parse_inline_table(toml_context *ctx, toml_table *tab) {
    if (eat_token(ctx, LBRACE, true, FLINE)) {
        return -1;
    }
    for (;;) {
        if (ctx->tok.tok == NEWLINE) {
            return e_syntax(ctx, ctx->tok.lineno, "newline not allowed in inline table");
        }
        if (ctx->tok.tok == RBRACE) { // until closing brace
            break;
        }

        if (ctx->tok.tok != STRING) {
            return e_syntax(ctx, ctx->tok.lineno, "expect a string");
        }
        if (parse_keyval(ctx, tab)) {
            return -1;
        }

        if (ctx->tok.tok == NEWLINE) {
            return e_syntax(ctx, ctx->tok.lineno, "newline not allowed in inline table");
        }
        /* on comma, continue to scan for next keyval */
        if (ctx->tok.tok == COMMA) {
            if (eat_token(ctx, COMMA, 1, FLINE)) {
                return -1;
            }
            continue;
        }
        break;
    }

    if (eat_token(ctx, RBRACE, 1, FLINE)) {
        return -1;
    }
    tab->readonly = 1;
    return 0;
}

int valtype(const char *val) {
    bool dummy = false;
    /* TODO: It would be nice to return enum values here instead of characters */
    if (*val == '\'' || *val == '"') {
        return 's';
    }
    if (toml_value_bool(val, &dummy)) {
        return 'b';
    }  
    if (toml_value_int(val, 0)) {
        return 'i';
    }
    if (toml_value_double(val, 0)) {
        return 'd';
    }
    return 'u'; // unknown
}

/* We are at '[...]' */
int parse_array(toml_context *ctx, toml_array *arr) {
    if (eat_token(ctx, LBRACKET, 0, FLINE)) {
        return -1;
    }
    for (;;) {
        if (skip_newlines(ctx, 0)) {
            return -1;
        }
        if (ctx->tok.tok == RBRACKET) { // until ]
            break;
        }

        switch (ctx->tok.tok) {
            case STRING: {
                // set array kind if this will be the first entry
                if (arr->kind == 0) {
                    arr->kind = 'v';
                } else if (arr->kind != 'v') {
                    arr->kind = 'm';
                }
                char *val = ctx->tok.ptr;
                int vlen = ctx->tok.len;

                // make a new value in array
                toml_arritem *newval = create_value_in_array(ctx, arr);
                if (!newval) {
                    return e_outofmemory(ctx, FLINE);
                }
                if (!(newval->val = toml_strndup(val, vlen))) {
                    return e_outofmemory(ctx, FLINE);
                }
                newval->valtype = valtype(newval->val);

                // set array type if this is the first entry
                if (arr->nitem == 1) {
                    arr->type = newval->valtype;
                } else if (arr->type != newval->valtype) {
                    arr->type = 'm'; // mixed
                }
                if (eat_token(ctx, ctx->tok.tok, 0, FLINE)) {
                    return -1;
                }
                break;
            }
            case LBRACKET: { /* [ [array], [array] ... ] */
                /* set the array kind if this will be the first entry */
                if (arr->kind == 0) {
                    arr->kind = 'a';
                } else if (arr->kind != 'a') {
                    arr->kind = 'm';
                }
                toml_array *subarr = create_array_in_array(ctx, arr);
                if (!subarr) {
                    return -1;
                }
                if (parse_array(ctx, subarr)) {
                    return -1;
                }
                break;
            }
            case LBRACE: { /* [ {table}, {table} ... ] */
                /* set the array kind if this will be the first entry */
                if (arr->kind == 0) {
                    arr->kind = 't';
                } else if (arr->kind != 't') {
                    arr->kind = 'm';
                }
                toml_table *subtab = create_table_in_array(ctx, arr);
                if (!subtab) {
                    return -1;
                }
                if (parse_inline_table(ctx, subtab)) {
                    return -1;
                }
                break;
            }
            default:
                return e_syntax(ctx, ctx->tok.lineno, "syntax error");
        }

        if (skip_newlines(ctx, 0)) {
            return -1;
        }
        /* on comma, continue to scan for next element */
        if (ctx->tok.tok == COMMA) {
            if (eat_token(ctx, COMMA, 0, FLINE)) {
                return -1;
            }
            continue;
        }
        break;
    }
    if (eat_token(ctx, RBRACKET, 1, FLINE)) {
        return -1;
    }
    return 0;
}

/* handle lines like these:
   key = "value"
   key = [ array ]
   key = { table } */
int parse_keyval(toml_context *ctx, toml_table *tab) {
    if (tab->readonly) {
        return e_forbid(ctx, ctx->tok.lineno, "cannot insert new entry into existing table");
    }

    toml_token key = ctx->tok;
    if (eat_token(ctx, STRING, 1, FLINE)) {
        return -1;
    }
    if (ctx->tok.tok == DOT) {
        /* handle inline dotted key. e.g.
           physical.color = "orange"
           physical.shape = "round" */
        toml_table *subtab = 0;
        {
            int keylen;
            char *subtabstr = normalize_key(ctx, key, &keylen);
            if (!subtabstr) {
                return -1;
            }
            subtab = toml_table_table(tab, subtabstr);
            if (subtab) {
                subtab->keylen = keylen;
            }
            xfree(subtabstr);
        }
        if (!subtab) {
            subtab = create_keytable_in_table(ctx, tab, key);
            if (!subtab) {
                return -1;
            }
        }
        if (next_token(ctx, true)) {
            return -1;
        }
        if (parse_keyval(ctx, subtab)) {
            return -1;
        }
        return 0;
    }

    if (ctx->tok.tok != EQUAL) {
        return e_syntax(ctx, ctx->tok.lineno, "missing =");
    }
    if (next_token(ctx, false)) {
        return -1;
    }
    switch (ctx->tok.tok) {
        case STRING: { // key = "value"
            toml_keyval *keyval = create_keyval_in_table(ctx, tab, key);
            if (!keyval) {
                return -1;
            }
            toml_token val = ctx->tok;

            assert(keyval->val == 0);
            if (!(keyval->val = toml_strndup(val.ptr, val.len))) {
                return e_outofmemory(ctx, FLINE);
            }

            if (next_token(ctx, true)) {
                return -1;
            }
            return 0;
        }
        case LBRACKET: { /* key = [ array ] */
            toml_array *arr = create_keyarray_in_table(ctx, tab, key, 0);
            if (!arr) {
                return -1;
            }
            if (parse_array(ctx, arr)) {
                return -1;
            }
            return 0;
        }
        case LBRACE: { /* key = { table } */
            toml_table *nxttab = create_keytable_in_table(ctx, tab, key);
            if (!nxttab) {
                return -1;
            }
            if (parse_inline_table(ctx, nxttab)) {
                return -1;
            }
            return 0;
        }
        default:
            return e_syntax(ctx, ctx->tok.lineno, "syntax error");
    }
    return 0;
}

/* at [x.y.z] or [[x.y.z]]
 * Scan forward and fill tabpath until it enters ] or ]]
 * There will be at least one entry on return. */
int fill_tabpath(toml_context *ctx) {
    // clear tpath
    for (int i = 0; i < ctx->tpath.top; i++) {
        char **p = &ctx->tpath.key[i];
        xfree(*p);
        *p = 0;
    }
    ctx->tpath.top = 0;

    for (;;) {
        if (ctx->tpath.top >= 10) {
            return e_syntax(ctx, ctx->tok.lineno, "table path is too deep; max allowed is 10.");
        }
        if (ctx->tok.tok != STRING) {
            return e_syntax(ctx, ctx->tok.lineno, "invalid or missing key");
        }
        int keylen;
        char *key = normalize_key(ctx, ctx->tok, &keylen);
        if (!key) {
            return -1;
        }
        ctx->tpath.tok[ctx->tpath.top] = ctx->tok;
        ctx->tpath.key[ctx->tpath.top] = key;
        ctx->tpath.keylen[ctx->tpath.top] = keylen;
        ctx->tpath.top++;

        if (next_token(ctx, true)) {
            return -1;
        }
        if (ctx->tok.tok == RBRACKET) {
            break;
        }
        if (ctx->tok.tok != DOT) {
            return e_syntax(ctx, ctx->tok.lineno, "invalid key");
        }
        if (next_token(ctx, true)) {
            return -1;
        }
    }

    if (ctx->tpath.top <= 0) {
        return e_syntax(ctx, ctx->tok.lineno, "empty table selector");
    }
    return 0;
}

/* Walk tabpath from the root, and create new tables on the way.
 * Sets ctx->curtab to the final table. */
int walk_tabpath(toml_context *ctx) {
    toml_table *curtab = ctx->root; // start from root

    for (int i = 0; i < ctx->tpath.top; i++) {
        const char *key = ctx->tpath.key[i];
        int keylen = ctx->tpath.keylen[i];

        toml_keyval *nextval = 0;
        toml_array *nextarr = 0;
        toml_table *nexttab = 0;
        switch (check_key(curtab, key, &nextval, &nextarr, &nexttab)) {
            case 't': // found a table. nexttab is where we will go next.
                break;
            case 'a': // found an array. nexttab is the last table in the array.
                if (nextarr->kind != 't' || nextarr->nitem == 0) {
                    return e_internal(ctx, FLINE);
                }
                nexttab = nextarr->item[nextarr->nitem - 1].tab;
                break;
            case 'v':
                return e_keyexists(ctx, ctx->tpath.tok[i].lineno);
            default: { // Not found. Let's create an implicit table.
                int n = curtab->ntab;
                toml_table **base = (toml_table **)expand_ptrarr((void **)curtab->tab, n);
                if (base == 0) {
                    return e_outofmemory(ctx, FLINE);
                }
                curtab->tab = base;
                if ((base[n] = (toml_table *)toml_calloc(1, sizeof(*base[n]))) == 0) {
                    return e_outofmemory(ctx, FLINE);
                }
                if ((base[n]->key = toml_strdup(key)) == 0) {
                    return e_outofmemory(ctx, FLINE);
                }
                base[n]->keylen = keylen;
                nexttab = curtab->tab[curtab->ntab++];
                // tabs created by walk_tabpath are considered implicit
                nexttab->implicit = true;
            }; break;
        }
        curtab = nexttab; // switch to next tab
    }

    ctx->curtab = curtab; // save it
    return 0;
}

/* handle lines like [x.y.z] or [[x.y.z]] */
int parse_select(toml_context *ctx) {
    assert(ctx->tok.tok == LBRACKET);

    /* true if [[ */
    int llb = (ctx->tok.ptr + 1 < ctx->stop && ctx->tok.ptr[1] == '[');
    /* need to detect '[[' on our own because next_token() will skip whitespace,
       and '[ [' would be taken as '[[', which is wrong. */

    /* eat [ or [[ */
    if (eat_token(ctx, LBRACKET, 1, FLINE)) {
        return -1;
    }
    if (llb) {
        assert(ctx->tok.tok == LBRACKET);
        if (eat_token(ctx, LBRACKET, 1, FLINE)) {
            return -1;
        }
    }

    if (fill_tabpath(ctx)) {
        return -1;
    }

    /* For [x.y.z] or [[x.y.z]], remove z from tpath. */
    toml_token z = ctx->tpath.tok[ctx->tpath.top - 1];
    xfree(ctx->tpath.key[ctx->tpath.top - 1]);
    ctx->tpath.top--;

    /* set up ctx->curtab */
    if (walk_tabpath(ctx)) {
        return -1;
    }

    if (!llb) {
        /* [x.y.z] -> create z = {} in x.y */
        toml_table *curtab = create_keytable_in_table(ctx, ctx->curtab, z);
        if (!curtab) {
            return -1;
        }
        ctx->curtab = curtab;
    } else {
        /* [[x.y.z]] -> create z = [] in x.y */
        toml_array *arr = 0;
        {
            int keylen;
            char *zstr = normalize_key(ctx, z, &keylen);
            if (!zstr) {
                return -1;
            }
            arr = toml_table_array(ctx->curtab, zstr);
            if (arr) {
                arr->keylen = keylen;
            }
            xfree(zstr);
        }
        if (!arr) {
            arr = create_keyarray_in_table(ctx, ctx->curtab, z, 't');
            if (!arr) {
                return -1;
            }
        }
        if (arr->kind != 't') {
            return e_syntax(ctx, z.lineno, "array mismatch");
        }
        /* add to z[] */
        toml_table *dest = NULL;
        {
            toml_table *t = create_table_in_array(ctx, arr);
            if (!t) {
                return -1;
            }

            if ((t->key = toml_strdup("__anon__")) == 0) {
                return e_outofmemory(ctx, FLINE);
            }
            dest = t;
        }

        ctx->curtab = dest;
    }

    if (ctx->tok.tok != RBRACKET) {
        return e_syntax(ctx, ctx->tok.lineno, "expects ]");
    }
    if (llb) {
        if (!(ctx->tok.ptr + 1 < ctx->stop && ctx->tok.ptr[1] == ']')) {
            return e_syntax(ctx, ctx->tok.lineno, "expects ]]");
        }
        if (eat_token(ctx, RBRACKET, 1, FLINE)) {
            return -1;
        }
    }

    if (eat_token(ctx, RBRACKET, 1, FLINE)) {
        return -1;
    }
    if (ctx->tok.tok != NEWLINE) {
        return e_syntax(ctx, ctx->tok.lineno, "extra chars after ] or ]]");
    }
    return 0;
}

toml_table *toml_parse(char *toml, char *errbuf, int errbufsz) {
    toml_context ctx;

    // clear errbuf
    if (errbufsz <= 0) {
        errbufsz = 0;
    }
    if (errbufsz > 0) {
        errbuf[0] = 0;
    }

    // init context
    memset(&ctx, 0, sizeof(ctx));
    ctx.start = toml;
    ctx.stop = ctx.start + strlen(toml);
    ctx.errbuf = errbuf;
    ctx.errbufsz = errbufsz;

    // start with an artificial newline of length 0
    ctx.tok.tok = NEWLINE;
    ctx.tok.lineno = 1;
    ctx.tok.ptr = toml;
    ctx.tok.len = 0;

    // make a root table
    if ((ctx.root = toml_calloc(1, sizeof(*ctx.root))) == 0) {
        e_outofmemory(&ctx, FLINE);
        return NULL; // Do not goto fail, root table not set up yet
    }

    // set root as default table
    ctx.curtab = ctx.root;

    // Scan forward until EOF
    for (toml_token tok = ctx.tok; !tok.eof; tok = ctx.tok) {
        switch (tok.tok) {
            case NEWLINE:
                if (next_token(&ctx, true)) {
                    goto fail;
                }
                break;

            case STRING:
                if (parse_keyval(&ctx, ctx.curtab)) {
                    goto fail;
                }

                if (ctx.tok.tok != NEWLINE) {
                    e_syntax(&ctx, ctx.tok.lineno, "extra chars after value");
                    goto fail;
                }

                if (eat_token(&ctx, NEWLINE, 1, FLINE)) {
                    goto fail;
                }
                break;

            case LBRACKET: /* [ x.y.z ] or [[ x.y.z ]] */
                if (parse_select(&ctx)) {
                    goto fail;
                }
                break;

            default:
                e_syntax(&ctx, tok.lineno, "syntax error");
                goto fail;
        }
    }

    // success
    for (int i = 0; i < ctx.tpath.top; i++) {
        xfree(ctx.tpath.key[i]);
    }
    return ctx.root;

fail:
    // Something bad has happened. Free resources and return error.
    for (int i = 0; i < ctx.tpath.top; i++) {
        xfree(ctx.tpath.key[i]);
    }
    toml_table_free(ctx.root);
    return NULL;
}

toml_table *toml_parse_file(const char *filename, char *errbuf, int errbufsz) {
    int bufsz = 0;
    char *buf = 0;
    int off = 0;
    int inc = 1024;

    FILE *fp = fopen(filename,"r");
    if (!fp) {
        snprintf(errbuf, errbufsz, "Could not open file\n");
        return NULL;
    }

    while (!feof(fp)) {
        if (bufsz == 1024 * 20) { // Increment buffer by 20k after 20k.
            inc = 1024 * 20;
        }
        if (off == bufsz) {
            int xsz = bufsz + inc;
            char *x = expand(buf, bufsz, xsz);
            if (!x) {
                snprintf(errbuf, errbufsz, "Out of memory");
                xfree(buf);
                return NULL;
            }
            buf = x;
            bufsz = xsz;
        }

        int n = fread(buf + off, 1, bufsz - off, fp);
        if (ferror(fp)) {
            snprintf(errbuf, errbufsz, "Error reading file");
            xfree(buf);
            return NULL;
        }
        off += n;
    }

    // tag on a NULL to cap the string
    if (off == bufsz) {
        int xsz = bufsz + 1;
        char *x = expand(buf, bufsz, xsz);
        if (!x) {
            snprintf(errbuf, errbufsz, "out of memory");
            xfree(buf);
            return NULL;
        }
        buf = x;
        bufsz = xsz;
    }
    buf[off] = 0;

    // parse it, cleanup and finish.
    toml_table *ret = toml_parse(buf, errbuf, errbufsz);
    xfree(buf);
    fclose(fp);
    return ret;
}

void toml_table_free(toml_table *p) { 
    if (!p) {
        return;
    }
    xfree(p->key);

    for (int i = 0; i < p->nkval; i++) {
        xfree_kval(p->kval[i]);
    }
    xfree(p->kval);

    for (int i = 0; i < p->narr; i++) {
        xfree_arr(p->arr[i]);
    }
    xfree(p->arr);

    for (int i = 0; i < p->ntab; i++) {
        toml_table_free(p->tab[i]);
    }
    xfree(p->tab);
    xfree(p);
}

void toml_string_free(char *str) {
    free(str);
}

void set_token(toml_context *ctx, TomlTokenType tok, int lineno, char *ptr, int len) {
    toml_token t;
    t.tok    = tok;
    t.lineno = lineno;
    t.ptr    = ptr;
    t.len    = len;
    t.eof    = 0;
    ctx->tok = t;
}

void set_eof(toml_context *ctx, int lineno) {
    set_token(ctx, NEWLINE, lineno, ctx->stop, 0);
    ctx->tok.eof = 1;
}

int scan_string(toml_context *ctx, char *p, int lineno, bool dotisspecial) {
    char *orig = p;

    // Literal multiline.
    if (strncmp(p, "'''", 3) == 0) {
        char *q = p + 3;
        while (true) {
            q = strstr(q, "'''");
            if (q == 0) {
                return e_syntax(ctx, lineno, "unterminated triple-s-quote");
            }
            int i = 0;
            while (q[3] == '\'') {
                i++;
                if (i >= 3) {
                    return e_syntax(ctx, lineno, "too many ''' in triple-s-quote");
                }
                q++;
            }
            break;
        }
        set_token(ctx, STRING, lineno, orig, q + 3 - orig);
        return 0;
    }

    // Multiline.
    if (strncmp(p, "\"\"\"", 3) == 0) {
        char *q = p + 3;
        while (true) {
            q = strstr(q, "\"\"\"");
            if (q == 0) {
                return e_syntax(ctx, lineno, "unterminated triple-d-quote");
            }
            if (q[-1] == '\\') {
                q++;
                continue;
            }
            int i = 0;
            while (q[3] == '\"') {
                i++;
                if (i >= 3) {
                    return e_syntax(ctx, lineno, "too many \"\"\" in triple-d-quote");
                }
                q++;
            }
            break;
        }

        // the string is [p+3, q-1]
        int hexreq = 0; // #hex required
        bool escape = false;
        for (p += 3; p < q; p++) {
            if (escape) {
                escape = false;
                if (strchr("btnfr\"\\", *p)) {
                    continue;
		}
                if (*p == 'u') {
                    hexreq = 4;
                    continue;
                }
                if (*p == 'U') {
                    hexreq = 8;
                    continue;
                }
                if (p[strspn(p, " \t\r")] == '\n') {
                    continue; /* allow for line ending backslash */
                }
                return e_syntax(ctx, lineno, "bad escape char");
            }
            if (hexreq) {
                hexreq--;
                if (strchr("0123456789ABCDEFabcdef", *p)) {
                    continue;
                }
                return e_syntax(ctx, lineno, "expect hex char");
            }
            if (*p == '\\') {
                escape = true;
                continue;
            }
        }
        if (escape) {
            return e_syntax(ctx, lineno, "expect an escape char");
        }
        if (hexreq) {
            return e_syntax(ctx, lineno, "expected more hex char");
        }
        set_token(ctx, STRING, lineno, orig, q + 3 - orig);
        return 0;
    }

    // Literal string.
    if (*p == '\'') {
        for (p++; *p && *p != '\n' && *p != '\''; p++);
        if (*p != '\'') {
            return e_syntax(ctx, lineno, "unterminated s-quote");
        }
        set_token(ctx, STRING, lineno, orig, p + 1 - orig);
        return 0;
    }

    // Basic String.
    if (*p == '\"') {
        int hexreq = 0; // #hex required
        bool escape = false;
        for (p++; *p; p++) {
            if (escape) {
                escape = false;
                if (strchr("btnfr\"\\", *p)) {
                    continue;
                }
                if (*p == 'u') {
                    hexreq = 4;
                    continue;
                }
                if (*p == 'U') {
                    hexreq = 8;
                    continue;
                }
                return e_syntax(ctx, lineno, "bad escape char");
            }
            if (hexreq) {
                hexreq--;
                if (strchr("0123456789ABCDEFabcdef", *p)) {
                    continue;
                }
                return e_syntax(ctx, lineno, "expect hex char");
            }
            if (*p == '\\') {
                escape = true;
                continue;
            }
            if (*p == '\n' || *p == '"') {
                break;
            }
        }
        if (*p != '"') {
            return e_syntax(ctx, lineno, "unterminated quote");
        }
        set_token(ctx, STRING, lineno, orig, p + 1 - orig);
        return 0;
    }

    // literals
    for (; *p && *p != '\n'; p++) {
        int ch = *p;
        if (ch == '.' && dotisspecial) {
            break;
        }
        if ('A' <= ch && ch <= 'Z') {
            continue;
        }
        if ('a' <= ch && ch <= 'z') {
            continue;
        }
        if (strchr("0123456789+-_.", ch)) {
            continue;
        }
        break;
    }

    set_token(ctx, STRING, lineno, orig, p - orig);
    return 0;
}

int next_token(toml_context *ctx, bool dotisspecial) {
    // Eat this tok.
    char *p = ctx->tok.ptr;
    int lineno = ctx->tok.lineno;
    for (int i = 0; i < ctx->tok.len; i++) {
        if (*p++ == '\n') {
            lineno++;
        }
    }

    // Generate next token
    while (p < ctx->stop) {
        if (*p == '#') { // Skip comment. stop just before the \n.
            for (p++; p < ctx->stop && *p != '\n'; p++);
            continue;
        }

        if (dotisspecial && *p == '.') {
            set_token(ctx, DOT, lineno, p, 1);
            return 0;
        }

        switch (*p) {
            case ',':
                set_token(ctx, COMMA, lineno, p, 1);
                return 0;
            case '=':
                set_token(ctx, EQUAL, lineno, p, 1);
                return 0;
            case '{':
                set_token(ctx, LBRACE, lineno, p, 1);
                return 0;
            case '}':
                set_token(ctx, RBRACE, lineno, p, 1);
                return 0;
            case '[':
                set_token(ctx, LBRACKET, lineno, p, 1);
                return 0;
            case ']':
                set_token(ctx, RBRACKET, lineno, p, 1);
                return 0;
            case '\n':
                set_token(ctx, NEWLINE, lineno, p, 1);
                return 0;
            case '\r': case ' ': case '\t': // ignore white spaces
                p++;
                continue;
        }
        return scan_string(ctx, p, lineno, dotisspecial);
    }
    set_eof(ctx, lineno);
    return 0;
}

const char *toml_table_key(const toml_table *tab, int keyidx, int *keylen) {
    if (keyidx < tab->nkval) {
        *keylen = tab->kval[keyidx]->keylen;
        return tab->kval[keyidx]->key;
    }
    if ((keyidx -= tab->nkval) < tab->narr) {
        *keylen = tab->arr[keyidx]->keylen;
        return tab->arr[keyidx]->key;
    }
    if ((keyidx -= tab->narr) < tab->ntab) {
        *keylen = tab->tab[keyidx]->keylen;
        return tab->tab[keyidx]->key;
    }
    *keylen = 0;
    return 0;
}

toml_unparsed toml_table_unparsed(const toml_table *tab, const char *key) {
    for (int i = 0; i < tab->nkval; i++) {
        if (strcmp(key, tab->kval[i]->key) == 0) {
            return tab->kval[i]->val;
        }
    }
    return 0;
}

toml_array *toml_table_array(const toml_table *tab, const char *key) {
    for (int i = 0; i < tab->narr; i++) {
        if (strcmp(key, tab->arr[i]->key) == 0) {
            return tab->arr[i];
        }
    }
    return NULL;
}

toml_table *toml_table_table(const toml_table *tab, const char *key) {
    for (int i  = 0; i < tab->ntab; i++) {
        if (strcmp(key, tab->tab[i]->key) == 0) {
            return tab->tab[i];
        }
    }
    return NULL;
}

toml_unparsed toml_array_unparsed(const toml_array *arr, int idx) {
    return (0 <= idx && idx < arr->nitem) ? arr->item[idx].val : 0;
}

int toml_table_len(const toml_table *tbl) {
    return tbl->nkval + tbl->narr + tbl->ntab;
}

int toml_array_len(const toml_array *arr) {
    return arr->nitem;
}

toml_array *toml_array_array(const toml_array *arr, int idx) {
    return (0 <= idx && idx < arr->nitem) ? arr->item[idx].arr : NULL;
}

toml_table *toml_array_table(const toml_array *arr, int idx) {
    return (0 <= idx && idx < arr->nitem) ? arr->item[idx].tab : NULL;
}


bool is_leap(int y) { 
    return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0); 
}

/* Raw to boolean */
bool toml_value_bool(toml_unparsed src, bool *ret_) {
    if (!src) {
        return false;
    }
    bool *ret = ret_ ? ret_ : NULL;

    if (strcmp(src, "true") == 0) {
        *ret = true;
        return true;
    }
    if (strcmp(src, "false") == 0) {
        *ret = false;
        return true;
    }
    return false;
}

/* Raw to integer */
bool toml_value_int(toml_unparsed src, int64_t *ret_) {
    if (!src) {
        return false;
    }
    char buf[100];
    char *p = buf;
    char *q = p + sizeof(buf);
    const char *s = src;
    int base = 0;
    int64_t dummy;
    int64_t *ret = ret_ ? ret_ : &dummy;
    bool have_sign = false;

    if (s[0] == '+' || s[0] == '-') { /* allow +/- */
        have_sign = true;
        *p++ = *s++;
    }

    if (s[0] == '_') { /* disallow +_100 */
        return false;
    }

    if (s[0] == '0') { // if 0* ...
        switch (s[1]) {
            case 'x': base = 16; s += 2; break;
            case 'o': base = 8;  s += 2; break;
            case 'b': base = 2;  s += 2; break;
            case '\0':
                return *ret = 0, true;
            default:
                if (s[1]) { // ensure no other digits after it
                    return false;
                }
        }
        if (!*s) {
            return false;
        }
        if (have_sign || s[0] == '_') {   // disallow +0xff, -0xff. disallow 0x_, 0o_, 0b_
            return false;
        }
    }

    while (*s && p < q) { // just strip underscores and pass to strtoll
        int ch = *s++;
        if (ch == '_') {
            if (s[0] == '_' || s[0] == '\0') {  // disallow '__', and numbers cannot end with '_'
                return false;
            }
            continue; // skip _
        }
        *p++ = ch;
    }

    if (*s || p == q) { // if not at end-of-string or we ran out of buffer ...
        return false;
    }
    *p = 0; // cap with NUL

    // Run strtoll on buf to get the integer
    char *endp = NULL;
    errno = 0;
    *ret = strtoll(buf, &endp, base);
    return (errno || *endp) ? false : true;
}

bool toml_value_double(toml_unparsed src, double *ret_) {
    if (!src) {
        return false;
    }

    char buf[100];
    char *p = buf;
    char *q = p + sizeof(buf);
    const char *s = src;
    double dummy;
    double *ret = ret_ ? ret_ : &dummy;
    bool have_us = false;

    if (s[0] == '+' || s[0] == '-') { // allow +/-
        *p++ = *s++;
    }

    if (s[0] == '_') { // disallow +_1.00
        return false;
    }

    { // decimal point, if used, must be surrounded by at least one digit on each side
        char *dot = strchr(s, '.');
        if (dot) {
            if (dot == s || !isdigit(dot[-1]) || !isdigit(dot[1])) {
                return false;
            }
        }
    }

    // zero must be followed by . or 'e', or NUL
    if (s[0] == '0' && s[1] && !strchr("eE.", s[1])) {
        return false;
    }

    // just strip underscores and pass to strtod
    while (*s && p < q) {
        int ch = *s++;
        if (ch == '_') {
            have_us = true;
            if (s[0] == '_' || s[0] == 'e' || s[0] == 0) { // disallow '__', disallow _e and disallow last char _
                return false;
            }
            continue; // skip _
        }
        if (ch == 'I' || ch == 'N' || ch == 'F' || ch == 'A') { // inf and nan are case-sensitive.
            return false;
        }
        if (ch == 'e' && s[0] == '_') { // disallow e_
            return false;
        }
        *p++ = ch;
    }
    if (*s || p == q) {
        return false; // reached end of string or buffer is full?
    }
    *p = 0; // cap with NUL

    // Run strtod on buf to get the value
    char *endp = NULL;
    errno = 0;
    *ret = strtod(buf, &endp);
    if (errno || *endp) {
        return false;
    }
    if (have_us && (isnan(*ret) || isinf(*ret))) {
        return false;
    }
    return true;
}

bool toml_value_string(toml_unparsed src, char **ret, int *len) {
    bool multiline = false;
    const char *sp;
    const char *sq;

    *ret = 0;
    if (!src) {
        return false;
    }
    // First char must be a s-quote or d-quote
    int qchar = src[0];
    const int srclen = strlen(src);
    if (!(qchar == '\'' || qchar == '"')) {
        return false;
    }

    // triple quotes?
    if (qchar == src[1] && qchar == src[2]) {
        multiline = true;      // triple-quote implies multiline
        sp = src + 3;          // first char after quote
        sq = src + srclen - 3; // first char of ending quote

        if (!(sp <= sq && sq[0] == qchar && sq[1] == qchar && sq[2] == qchar)) {
            return false; // last 3 chars in src must be qchar
        }

        if (sp[0] == '\n') { // skip new line immediate after qchar
            sp++;
        } else if (sp[0] == '\r' && sp[1] == '\n') {
            sp += 2;
        }
    } else {
        sp = src + 1;          // first char after quote
        sq = src + srclen - 1; // ending quote
        if (!(sp <= sq && *sq == qchar)) { // last char in src must be qchar
            return false;
        }
    }

    /* at this point:
    * sp points to first valid char after quote.
    * sq points to one char beyond last valid char.
    * string len is (sq - sp). */
    if (qchar == '\'') {
        *ret = norm_lit_str(sp, sq - sp, len, multiline, false, 0, 0);
    } else {
        *ret = norm_basic_str(sp, sq - sp, len, multiline, false, 0, 0);
    }
    return *ret ? true : false;
}

toml_value toml_array_string(const toml_array *arr, int idx) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_string(toml_array_unparsed(arr, idx), &ret.value.String, &ret.value.StringLen);
    return ret;
}

toml_value toml_array_bool(const toml_array *arr, int idx) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_bool(toml_array_unparsed(arr, idx), &ret.value.Boolean);
    return ret;
}

toml_value toml_array_int(const toml_array *arr, int idx) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_int(toml_array_unparsed(arr, idx), &ret.value.Integer);
    return ret;
}

toml_value toml_array_double(const toml_array *arr, int idx) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_double(toml_array_unparsed(arr, idx), &ret.value.Decimal);
    return ret;
}

toml_value toml_table_string(const toml_table *tbl, const char *key) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    toml_unparsed raw = toml_table_unparsed(tbl, key);
    if (raw) {
        ret.ok = toml_value_string(raw, &ret.value.String, &ret.value.StringLen);
    }
    return ret;
}

toml_value toml_table_bool(const toml_table *tbl, const char *key) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_bool(toml_table_unparsed(tbl, key), &ret.value.Boolean);
    return ret;
}

toml_value toml_table_int(const toml_table *tbl, const char *key) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_int(toml_table_unparsed(tbl, key), &ret.value.Integer);
    return ret;
}

toml_value toml_table_double(const toml_table *tbl, const char *key) {
    toml_value ret;
    memset(&ret, 0, sizeof(ret));
    ret.ok = toml_value_double(toml_table_unparsed(tbl, key), &ret.value.Decimal);
    return ret;
}

