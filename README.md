# Form Crawler

A CLI tool to crawl websites and extract all URLs and forms with their parameters.

## Installation

```bash
go build -o form-crawler.exe
```

## Usage

```bash
form-crawler -url <target-url> [options]
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL to crawl (required) | - |
| `-proxy` | Proxy URL (HTTP/SOCKS5) | - |
| `-cookie` | Cookie header value | - |
| `-session` | Session ID | - |
| `-token` | Bearer authorization token | - |
| `-dont-access` | URL patterns to skip (comma-separated, supports regex) | - |
| `-depth` | Maximum crawl depth | 3 |
| `-verbose` | Enable verbose output | false |

## Examples

```bash
# Basic crawl
form-crawler -url https://example.com

# With proxy (e.g., Burp Suite)
form-crawler -url https://example.com -proxy http://127.0.0.1:8080

# With authentication
form-crawler -url https://example.com -cookie "session=abc123"
form-crawler -url https://example.com -token "eyJhbGciOi..."

# Skip specific URLs
form-crawler -url https://example.com -dont-access "logout,delete,/admin.*"

# Deep crawl with verbose output
form-crawler -url https://example.com -depth 10 -verbose
```

## Output Format

Results are displayed in CSV format:

```
Method,URL,Params
```

- **URLs**: `GET,<url>,`
- **Forms**: `<METHOD>,<action-url>,<param1>&<param2>&...`
