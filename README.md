# keytrawl

Streaming secret finder for raw bytes: private keys, cloud tokens and configuration secrets, each validated before it is reported.

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(keytrawl REQUIRED)
target_link_libraries(app PRIVATE keytrawl::keytrawl)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs keytrawl)
```

## Single-file form

`scripts/amalgamate.sh` writes `dist/keytrawl/keytrawl.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define KTW_IMPLEMENTATION
#include "keytrawl/keytrawl.h"
```

Define `KTW_STATIC` as well to keep every function private to that file.

## Usage

See [`examples/basic.c`](examples/basic.c). The header `include/keytrawl/keytrawl.h` is the
API reference.

Conventions:

- every function that can fail returns `KTW_OK` or an error code; `ktw_strerror` describes it
- what `ktw_x_create` returns is released only by `ktw_x_destroy`, which accepts `NULL`
- functions never take ownership of their arguments; returned pointers belong to the library
- pass your own allocator to `ktw_buf_create`, or `NULL` for `malloc`/`free`

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
