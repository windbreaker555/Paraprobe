# ParaProbe 🔍

An advanced parameter discovery tool for web applications that identifies hidden GET and POST parameters through intelligent fuzzing and response analysis. Detects parameters using multiple techniques including status code changes, response length analysis, reflection detection, and error message patterns.

## Installation

```bash
git clone https://github.com/yourusername/paraprobe.git
cd paraprobe
pip3 install requests
```

## Usage

**Basic scan:**
```bash
python3 paraprobe.py -u https://api.example.com/endpoint -w params.txt
```

**POST method:**
```bash
python3 paraprobe.py -u https://example.com/api -w params.txt -m POST
```

**Authenticated scan:**
```bash
python3 paraprobe.py -u https://example.com/api -w params.txt -H "Cookie: session=abc123"
```

**With authorization header:**
```bash
python3 paraprobe.py -u https://api.example.com -w params.txt -H "Authorization: Bearer token"
```

**Follow redirects:**
```bash
python3 paraprobe.py -u https://example.com/endpoint -w params.txt --follow-redirects
```

**Export results:**
```bash
python3 paraprobe.py -u https://example.com/api -w params.txt -o results.json
```

**Stealth scan with delay:**
```bash
python3 paraprobe.py -u https://example.com/api -w params.txt -t 5 -d 0.5
```

**All options:**
```
-h, --help                 Show help message
-u, --url URL              Target URL (required)
-w, --wordlist FILE        Parameter wordlist (required)
-m, --method METHOD        HTTP method: GET or POST (default: GET)
-t, --threads NUM          Number of threads (default: 10)
-d, --delay FLOAT          Delay between requests (default: 0)
-H, --header HEADER        Custom header (repeatable)
-p, --placeholder VALUE    Placeholder value (default: FUZZ)
-s, --stable NUM           Baseline requests (default: 3)
-o, --output FILE          Export to JSON
--follow-redirects         Follow HTTP redirects
--no-color                 Disable colors
```

## Disclaimer

For authorized security testing only. Always obtain permission before testing any web application.
