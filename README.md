# [AIstudioProxyAPI](https://github.com/CJackHwang/AIstudioProxyAPI) Helper

This is a Man-in-the-Middle (MITM) proxy server implemented in Golang that can intercept AIStudio HTTPS requests and generate corresponding server certificates using a self-signed root certificate.

It's designed to work with [AIstudioProxyAPI](https://github.com/CJackHwang/AIstudioProxyAPI)

## Features

- Creates an HTTP proxy server (default port: 3120)
- Intercepts HTTPS requests for Google domains (also can be configured)
- Automatically Generates server certificates on-the-fly using a self-signed CA certificate
- Parse AIStudio responses to OpenAI compatible format

## Usage

### Certificate Generation

The project includes pre-generated CA certificates and keys. If you need to regenerate them, you can use the following commands:

```bash
openssl genrsa -out cert/ca.key 2048
openssl req -new -x509 -days 3650 -key cert/ca.key -out cert/ca.crt -subj "/C=CN/ST=Shanghai/L=Shanghai/O=AiStudioProxyHelper/OU=CA/CN=AiStudioProxyHelper CA/emailAddress=ca@example.com"
openssl rsa -in cert/ca.key -out cert/ca.key
```

### Building and Running

```bash
# Build the project
go build -o proxy-server

# Run with default configuration
./proxy-server

# Run with custom parameters
./proxy-server -port 3120 -api-port 3121 -sniff "example.com,api.example.org,*.google.com"

# Run with upstream proxy server
./proxy-server -proxy "http://user:password@proxy.example.com:8080"
./proxy-server -proxy "socks5://user:password@proxy.example.com:1080"
```

### Command Line Arguments

- `-port`: Proxy server port (default: 3120)
- `-api-port`: API server port (default: 3121)
- `-sniff`: Comma-separated list of domains to intercept
- `-proxy`: Upstream proxy server URL (e.g., http://user:pass@host:port, https://host:port, socks4://host:port, socks5://user:pass@host:port)


### Client Configuration

1. Install the CA certificate (`cert/ca.crt`) into your client device's trusted root certificate store
2. Configure your browser or system to use the proxy server (address: 127.0.0.1, port: 3120)

### Viewing Sniffed Data

```
curl -N -H "Cookie: SAPISID=your_sapisid_value" \
http://127.0.0.1:3121/getStreamResponse
```

### Viewing Sniffed Domains

```
curl http://127.0.0.1:3121/getSniffDomains
```

### Adding Sniff Domains

```
curl -X POST \
-H "Content-Type: application/json" \
-d '{"domain":"example.com"}' \
http://127.0.0.1:3121/addSniffDomain
```

### Deleting Sniff Domains

```
curl -X POST \
-H "Content-Type: application/json" \
-d '{"domain":"example.com"}' \
http://127.0.0.1:3121/removeSniffDomain
```


## How It Works

When a client connects to the proxy and attempts to establish an HTTPS connection:

1. The proxy checks if the domain is in the list of domains to intercept
2. If the domain should be intercepted:
   - The proxy generates a certificate for the domain signed by its CA
   - It establishes a TLS connection with the target server
   - It establishes a TLS connection with the client using the generated certificate
   - It forwards data between the client and server while recording the traffic
3. If the domain is not in the intercept list, it simply forwards the connection

## Technical Details

- The proxy automatically handles AIStudio gzipped and chunked responses
- For endpoints containing "GenerateContent", the proxy will record both request and response data
- The proxy uses a certificate cache to improve performance for frequently accessed domains

## Requirements

- Go 1.24.0 or higher

## License

[MIT](LICENSE)