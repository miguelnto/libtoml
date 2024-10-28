#ifndef TOML_H
#define TOML_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct toml_table     toml_table;
typedef struct toml_array     toml_array;
typedef struct toml_value     toml_value;
typedef struct toml_keyval    toml_keyval;
typedef struct toml_arritem   toml_arritem;

/* TODO: For some unknown reason a lot of functions in this lib returns -1 or 0 */
/* TODO: They also have weird names, like eat_token.. */
/* TODO: Sometimes 1 or 0 is passed as a func paremeter, instead of true or false. */

// TOML table.
struct toml_table {
    const char *key;       // Key for this table
    int keylen;            // Length of key.
    bool implicit;         // true if table was created implicitly
    bool readonly;         // true if no more modification is allowed

    int nkval;             // number of key-values in the table
    toml_keyval **kval;
    int narr;              // arrays in the table
    toml_array **arr;
    int ntab;              // number of tables in the table
    toml_table **tab;
};

// TOML array.
struct toml_array {
    const char *key; // key to this array
    int keylen;      // length of key.
    int kind;        // Item kind: 'v'alue, 'a'rray, or 't'able, 'm'ixed
    int type;        // The kind type: 'i'nt, 'd'ouble, 'b'ool, 's'tring, 'm'ixed
    int nitem;       // Number of items
    toml_arritem *item;
};

/* TOML array item. */
struct toml_arritem {
    int valtype; // The value type: 'i'nt, 'd'ouble, 'b'ool, 's'tring
    char *val;
    toml_array *arr;
    toml_table *tab;
};

// TOML key/value pair.
struct toml_keyval {
    const char *key; // key to this value
    int keylen;      // length of key
    const char *val; // the raw value
};

// Parsed TOML value. String value is guaranteed to be correct UTF-8.
struct toml_value {
    bool ok; // Was this value present?
    union {
        char *String;  // string value; must be freed after use
        /* TODO: Remove StringLen */
        int StringLen;  // string length, excluding the nulls.
        bool Boolean;   // bool value
        int64_t Integer;   // int value
        double Decimal;   // double value
    } value;
};

enum TomlTokenType {
    INVALID,
    DOT,
    COMMA,
    EQUAL,
    LBRACE,
    RBRACE,
    NEWLINE,
    LBRACKET,
    RBRACKET,
    STRING,
};
typedef enum TomlTokenType TomlTokenType;

typedef struct toml_token toml_token;
struct toml_token {
    TomlTokenType tok;
    int lineno;
    char *ptr; // points into context->start
    int len;
    int eof;
};

typedef struct toml_context toml_context;
struct toml_context {
    char *start;
    char *stop;
    char *errbuf;
    int errbufsz;

    toml_token tok;
    toml_table *root;
    toml_table *curtab;

    struct {
        int top;
        char *key[10];
        int keylen[10];
        toml_token tok[10];
    } tpath;
};

/* toml_parse() parses a TOML document from a string. Returns NULL on error, 
* with the error message stored in errbuf.
* toml_parse_file() is identical, but reads from a file.
* The table needs to be free'd after use, using toml_table_free(). */
extern toml_table *toml_parse(char *toml, char *errbuf, int errbufsz);
extern toml_table *toml_parse_file(const char *filename, char *errbuf, int errbufsz);
extern void toml_table_free(toml_table *p);
extern void toml_string_free(char *str);

/* Table functions.
* toml_table_len() gets the number of direct keys for this table;
* toml_table_key() gets the nth direct key in this table. */
extern int        toml_table_len       (const toml_table *table);
extern const char *toml_table_key      (const toml_table *table, int keyidx, int *keylen);
extern toml_value toml_table_string    (const toml_table *table, const char *key);
extern toml_value toml_table_bool      (const toml_table *table, const char *key);
extern toml_value toml_table_int       (const toml_table *table, const char *key);
extern toml_value toml_table_double    (const toml_table *table, const char *key);
extern toml_array *toml_table_array    (const toml_table *table, const char *key);
extern toml_table *toml_table_table    (const toml_table *table, const char *key);

// Array functions.
extern int        toml_array_len     (const toml_array *array);
extern toml_value toml_array_string  (const toml_array *array, int idx);
extern toml_value toml_array_bool    (const toml_array *array, int idx);
extern toml_value toml_array_int     (const toml_array *array, int idx);
extern toml_value toml_array_double  (const toml_array *array, int idx);
extern toml_array *toml_array_array    (const toml_array *array, int idx);
extern toml_table *toml_array_table    (const toml_array *array, int idx);

#endif

