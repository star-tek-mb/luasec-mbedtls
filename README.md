# luasec-mbedtls
Lua module for SSL/TLS using lightweight mbedTLS library

# Usage example
```lua
local tls = require('tls')
local socket = require('socket')

local sock = socket.connect('www.google.com', 443)
sock = tls.wrap(sock, {
    mode = 'client',
    verify = 'none'
})

sock:dohandshake()
print(sock:send('GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n'))
print(sock:receive('*a'))
```

# Build instructions
Prerequisites:
- CMake 3.10+
- Lua 5.1+
- C compiler

```bash
cd luasec-mbedtls
mkdir build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
```

# TODOS
- Update CMake file (Lua finding instead of hardcoded path to Lua)
- Realize non-blocking IO for handshake/read/write operations (timeouts)
- Compatibility with LuaSec?
- More crypto, tls, ssl, mbedTLS API?
- Error codes to string
- Stabilize luasec-mbedtls internal API



Contributions are welcome
