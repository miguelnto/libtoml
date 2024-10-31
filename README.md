# libtoml

libtoml is a C99 library for reading a subset of **TOML 1.0 files.**

It supports:

- [x] Comments
- [x] Key/Value pairs
- [x] String
- [x] Integer
- [x] Float
- [x] Boolean
- [x] Array
- [x] Table
- [x] Inline Table
- [x] Array of Tables

For more information on the TOML format, go to the [official website.](https://toml.io/en/v1.0.0)

## Requirements

- A C99 compiler
- GNU Make

## Installation

This library uses `GNU Make` for its building and installation process. You might need to run the following commands as root.

- Build:

```sh
make build
```

- Install:

```sh
make install
```

This will **build** and **install** the library.
By default the library will be installed in the `/usr/lib` folder. You can change this by editing the `Makefile`.

- Uninstall:

```sh
make uninstall
```

## Usage

I've provided a practical example under the [example](example/) directory. It should cover all you need to know to use the library effectively.

Having said that, take a look at a quick example bellow.

Let's say we have the following `config.toml` file:

```toml
[test]
text = "something"
num = 12
```

We can read the contents of `config.toml` like this:

```c
#include <stdio.h>
#include <toml.h>
#include <stdbool.h>

typedef struct Test Test;
struct Test {
  char *text;
  int num;
};

int main(void) {
  char errbf[300];
  Test test = {0};
  const char *filename = "config.toml";
  toml_table *tbl = toml_parse_file(filename, errbf, sizeof(errbf));
  if (!tbl) {
    fprintf(stderr, "Error when parsing toml file: %s\n", errbf);
    return 1;
  }
  toml_table *t = toml_table_table(tbl, "test");
  if (!t) {
    fprintf(stderr, "No table named <test>.");
    toml_table_free(tbl);
    return 1;
  }
  toml_value text = toml_table_string(t, "text");
  if (!text.ok) {
    fprintf(stderr,"Error when reading key <text>.");
    toml_table_free(tbl);
    return 1;
  } 
  toml_value num = toml_table_int(t, "num");
  if (!num.ok) {
    fprintf(stderr, "Error when reading key <num>.");
    toml_string_free(text.value.String);
    toml_table_free(tbl);
    return 1;
  }
  printf("text = %s\n", text.value.String);
  printf("num = %d\n", (int)num.value.Integer);
  toml_string_free(text.value.String);
  toml_table_free(tbl);
  return 0;
}
```

## Reference

For now I suggest reading the `toml.h` file if you want further information about the types and functions this library provides.

## TODO

The API is unlikely to change. I'll be focusing on cleaning the code and make some small changes here and there.

## Credits

This library is a fork and refactoring of [toml-c.](https://github.com/arp242/toml-c)
