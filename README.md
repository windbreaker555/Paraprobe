ParaProbe 🔍
An advanced parameter discovery tool for web applications that identifies hidden GET and POST parameters through intelligent fuzzing and response analysis. Designed for penetration testers and bug bounty hunters to uncover API endpoints, hidden functionality, and potential vulnerabilities.
Features

Smart Baseline Detection - Establishes stable baseline responses to minimize false positives
Multi-Method Support - Tests both GET and POST parameters
Multiple Detection Techniques:

HTTP status code changes
Response length differences
Content reflection analysis
Error message pattern matching


Multi-threaded Scanning - Fast, concurrent parameter testing
Authentication Support - Custom headers and cookies for authenticated endpoints
Redirect Handling - Option to follow or ignore HTTP redirects
Rate Limiting - Configurable delay between requests for stealth
Stability Checking - Multiple baseline requests to handle dynamic responses
JSON Export - Save discovered parameters for further analysis
Color-coded Output - Clear, organized results with visual feedback

Installation
bashgit clone https://github.com/yourusername/paraprobe.git
cd paraprobe
pip3 install requests
Usage
Basic Scan
bashpython3 paraprobe.py -u https://api.example.com/endpoint -w params.txt
POST Method
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -m POST
Authenticated Scan
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -H "Cookie: session=abc123" -H "Authorization: Bearer token"
Following Redirects
bashpython3 paraprobe.py -u https://example.com/endpoint -w params.txt --follow-redirects
High-Speed Scan
bashpython3 paraprobe.py -u https://api.example.com -w params.txt -t 20
Stealth Scan with Delay
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -t 5 -d 0.5
Export Results
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -o results.json
Command Line Options
Required Arguments:
  -u, --url URL              Target URL to scan
  -w, --wordlist FILE        Parameter wordlist file

Optional Arguments:
  -h, --help                 Show help message and exit
  -m, --method METHOD        HTTP method: GET or POST (default: GET)
  -t, --threads NUM          Number of concurrent threads (default: 10)
  -d, --delay FLOAT          Delay between requests in seconds (default: 0)
  -H, --header HEADER        Custom header (can be used multiple times)
  -p, --placeholder VALUE    Placeholder value for parameters (default: FUZZ)
  -s, --stable NUM           Baseline stability check requests (default: 3)
  -o, --output FILE          Export results to JSON file
  --follow-redirects         Follow HTTP redirects
  --no-color                 Disable colored output
Detection Methods
ParaProbe uses multiple heuristics to identify valid parameters:
1. Status Code Changes
Detects when a parameter causes a different HTTP response code (e.g., 200 instead of 404)
2. Response Length Analysis
Identifies significant changes in response size (>5% difference or >50 bytes)
3. Reflection Detection
Monitors when placeholder values appear in responses, indicating parameter processing
4. Error Message Patterns
Recognizes error messages that reference the parameter name:

"parameter 'X' is required"
"missing parameter X"
"invalid X"
"undefined variable X"

Authentication
For authenticated endpoints, use custom headers:
bash# Session cookie
python3 paraprobe.py -u https://example.com/api -w params.txt -H "Cookie: PHPSESSID=abc123; security=low"

# Bearer token
python3 paraprobe.py -u https://api.example.com -w params.txt -H "Authorization: Bearer eyJhbGc..."

# API key
python3 paraprobe.py -u https://api.example.com -w params.txt -H "X-API-Key: your_key_here"

# Multiple headers
python3 paraprobe.py -u https://example.com/api -w params.txt -H "Cookie: session=xyz" -H "X-CSRF-Token: token123"
Handling Redirects
If you encounter 302 redirects (common with authentication):
Option 1: Follow redirects
bashpython3 paraprobe.py -u https://example.com/endpoint -w params.txt --follow-redirects
Option 2: Add authentication cookies (recommended)
bashpython3 paraprobe.py -u https://example.com/endpoint -w params.txt -H "Cookie: session=..."
Creating Wordlists
ParaProbe requires a parameter wordlist. You can use the included params.txt or create your own:
Common parameter names to include:

id, user, username, email, token
page, limit, offset, sort, filter
search, query, q, keyword
action, cmd, command, debug
file, path, url, redirect
api_key, access_token, session

Sources for wordlists:

SecLists Parameters
Arjun Params
Custom wordlists based on target technology

Examples
Testing a REST API
bashpython3 paraprobe.py -u https://api.example.com/v1/users -w params.txt -m POST -H "Content-Type: application/json"
Testing with Authentication
bash# First, login and get session cookie from browser DevTools
python3 paraprobe.py -u https://app.example.com/api/data -w params.txt -H "Cookie: session_id=abc123xyz"
Bug Bounty Scanning
bash# Slower, stealthier scan
python3 paraprobe.py -u https://target.com/api/endpoint -w params.txt -t 5 -d 1 -o findings.json
Testing DVWA or Similar Labs
bash# Get session cookie after login, then:
python3 paraprobe.py -u "http://127.0.0.1/dvwa/vulnerabilities/fi/" -w params.txt -H "Cookie: PHPSESSID=your_session; security=low"
Output Format
Console Output
============================================================
ParaProbe - Parameter Discovery
============================================================
[*] Target: https://api.example.com/users
[*] Method: GET
[*] Threads: 10
[*] Wordlist: params.txt

[+] Loaded 500 parameters from wordlist
[*] Establishing baseline...
[+] Baseline established:
    Status Code: 200
    Response Length: 1523
    Reflection: False

[*] Starting parameter discovery...

[+] FOUND: id (Status: 200, Length: 2341, Reason: Length diff: 818)
[+] FOUND: user (Reason: Error message detected)
[+] FOUND: limit (Status: 200, Length: 1654, Reason: Length diff: 131)

============================================================
Scan Complete!
============================================================
[*] Total requests: 500
[*] Time elapsed: 4.52s
[*] Requests/sec: 110.62

[+] Found 3 parameters:

  → id
    Method: GET, Status: 200, Length: 2341, Reason: Length diff: 818
  → user
    Method: GET, Status: 200, Length: 1523, Reason: Error message detected
  → limit
    Method: GET, Status: 200, Length: 1654, Reason: Length diff: 131
JSON Export
json[
  {
    "param": "id",
    "method": "GET",
    "status": 200,
    "length": 2341,
    "reason": "Length: 2341 (diff: 818)"
  },
  {
    "param": "user",
    "method": "GET",
    "status": 200,
    "length": 1523,
    "reason": "Error message detected"
  }
]
Tips for Better Results
1. Use Quality Wordlists
Start with common parameters, then add technology-specific ones based on reconnaissance
2. Authenticate When Needed
Many endpoints require authentication. Always include session cookies or API keys
3. Test Both Methods
Some parameters only work with POST:
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -m GET -o get_results.json
python3 paraprobe.py -u https://example.com/api -w params.txt -m POST -o post_results.json
4. Adjust Thread Count

High thread count (20+): Fast but may trigger WAF/rate limits
Low thread count (5-10): Slower but stealthier

5. Use Delays for Stealth
Add delays to avoid detection:
bashpython3 paraprobe.py -u https://example.com/api -w params.txt -t 5 -d 0.5
6. Monitor Baseline Warnings
If baseline is unstable, results may be unreliable. Consider:

Reducing thread count
Adding delays
Checking for dynamic content (timestamps, CSRFs, etc.)

Troubleshooting
No Parameters Found

Check authentication: Add session cookies or API tokens
Try --follow-redirects: If getting 302 responses
Verify URL: Ensure the endpoint URL is correct
Test wordlist: Manually test a known parameter

Too Many False Positives

Reduce sensitivity: Baseline may be unstable due to dynamic content
Lower thread count: Multiple concurrent requests may cause variations
Add delays: Give server time to process requests consistently

Getting Blocked/Rate Limited

Reduce threads: Use -t 5 or lower
Add delays: Use -d 1 or higher
Use proxy: Route through proxy to avoid IP blocking (requires manual proxy setup)

Disclaimer
ParaProbe is intended for authorized security testing only.

✅ Use on systems you own or have explicit permission to test
✅ Use for authorized penetration tests and bug bounty programs
✅ Use for educational purposes in controlled environments
❌ Do not use on systems without authorization
❌ Do not use for malicious purposes
❌ Do not use to cause denial of service

Always obtain proper authorization before testing any web application. Unauthorized testing may be illegal.
Contributing
Contributions are welcome! Areas for improvement:

Additional detection heuristics
Support for JSON/XML payloads
Integration with Burp Suite
Machine learning for parameter prediction
Proxy support
