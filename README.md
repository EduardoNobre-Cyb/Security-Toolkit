# Security Toolkit

A comprehensive Python-based security toolkit for password checking, antivirus scanning, SSH log analysis, URL safety verification, and network port scanning.

**Created by Eduardo Nobre**

## Features

- **Password Checker** - Check if passwords have been leaked using the PwnedPasswords API
- **Antivirus Scanner** - Scan files for malware using VirusTotal API
  - Check file hash (fast, private)
  - Upload and scan files (for new/unknown files)
- **SSH Log Analyzer** - Analyze SSH authentication logs for failed login attempts
  - Detect suspicious activity
  - Geo-location tracking of failed attempts
  - High-risk country flagging
- **URL Safety Checker** - Check URLs for malicious content using VirusTotal
- **Port Scanner** - Scan target hosts for open ports
  - Scan common ports (fast)
  - Custom port ranges
  - Save results to file
  - Multi-threaded scanning for performance

## Requirements

- Python 3.8+
- Internet connection (for API calls)
- API Keys:
  - **VirusTotal API Key** (free tier available at https://www.virustotal.com/gui/home/upload)
  - Optional: **AbuseIPDB API Key** (for enhanced IP reputation)

## Installation

### Local Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd SecurityToolKit\ Python
```

2. Create configuration file:

```bash
cp config.example.ini config.ini
```

3. Edit `config.ini` with your API keys:

```ini
[API_KEYS]
avScanner = YOUR_VIRUSTOTAL_API_KEY

[SETTINGS]
threshold = 5
```

4. Install Python dependencies:

```bash
pip install -r requirements.txt
```

5. Run the toolkit:

```bash
python sec-tool.py
```

### Docker Setup

1. Build the container:

```bash
docker build -t security-toolkit:latest .
```

2. Configure `config.ini`:

```bash
cp config.example.ini config.ini
# Edit config.ini with your API keys
```

3. Run interactively:

```bash
docker-compose run --rm toolkit
```

Or run specific commands:

```bash
docker-compose run --rm toolkit --check-password "YourPassword"
docker-compose run --rm toolkit --scan-ports 192.168.1.1 --save-results
```

## Usage

### Interactive Menu

Run without arguments to access the interactive menu:

```bash
python sec-tool.py
```

Then select from:

1. Check Password (Pwned)
2. Scan File with VirusTotal
3. Analyze SSH Logs
4. URL Safety Check
5. Port Scanner
6. Exit

### Command Line Interface

#### Check Password

```bash
python sec-tool.py --check-password "your_password"
```

#### Scan File (Check Hash)

```bash
python sec-tool.py --scan-file /path/to/file
```

#### Upload and Scan File

```bash
python sec-tool.py --scan-file /path/to/file --upload
```

#### Analyze SSH Logs

```bash
python sec-tool.py --analyze-logs /var/log/auth.log --threshold 5
```

#### Check URL

```bash
python sec-tool.py --check-url "https://example.com"
```

#### Scan Ports

```bash
python sec-tool.py --scan-ports 192.168.1.1
```

#### Scan Custom Port Range

```bash
python sec-tool.py --scan-ports 192.168.1.1 --port-range 1-1000 --save-results
```

#### Show Version

```bash
python sec-tool.py --version
```

## Configuration

### config.ini

Create `config.ini` based on `config.example.ini`:

```ini
[API_KEYS]
# Your VirusTotal API key (get from https://www.virustotal.com)
avScanner = YOUR_API_KEY_HERE

[SETTINGS]
# Threshold for SSH log analysis (number of failed attempts to flag as suspicious)
threshold = 5
```

## Docker Usage

### Using docker-compose

Run interactive menu:

```bash
docker-compose run --rm toolkit
```

Run specific command:

```bash
docker-compose run --rm toolkit --check-password "test123"
```

### Docker Run

Password check:

```bash
docker run --rm \
  -v $(pwd)/config.ini:/app/config.ini \
  security-toolkit:latest \
  --check-password "password"
```

File scan:

```bash
docker run --rm \
  -v $(pwd)/config.ini:/app/config.ini \
  -v /path/to/file:/app/file \
  security-toolkit:latest \
  --scan-file /app/file
```

Port scan (save results):

```bash
docker run --rm \
  -v $(pwd)/config.ini:/app/config.ini \
  -v $(pwd)/results:/app/results \
  security-toolkit:latest \
  --scan-ports 192.168.1.1 --save-results
```

## Volumes

When using Docker, these directories are available:

- `./config.ini` - Mounted from host (configuration)
- `./results/` - Scan results and reports
- `./logs/` - Log files

## Examples

### Example 1: Check If Your Password Was Leaked

```bash
python sec-tool.py --check-password "MyPassword123!"
```

### Example 2: Analyze SSH Logs for Suspicious Activity

```bash
python sec-tool.py --analyze-logs /var/log/auth.log --threshold 3
```

### Example 3: Scan a File for Malware

```bash
python sec-tool.py --scan-file ~/Downloads/suspicious.exe
```

### Example 4: Check Website Safety

```bash
python sec-tool.py --check-url "https://example.com"
```

### Example 5: Find Open Ports on a Server

```bash
python sec-tool.py --scan-ports 192.168.1.1 --save-results
```

## API Integration

### VirusTotal

- **Free Tier**: 4 requests per minute
- **Premium**: Higher rate limits
- Get API key: https://www.virustotal.com/gui/home/upload

### Pwned Passwords

- **Free**: No API key required
- Uses SHA-1 hashing for privacy
- Data from https://haveibeenpwned.com

### IP Geolocation

- **Free**: ip-api.com (45 requests/minute limit)
- Returns: Country, City, ISP information

## Security Considerations

1. **API Keys**: Keep your VirusTotal API key private. Use environment variables or secure config management in production.
2. **Password Privacy**: The password checker uses SHA-1 hashing and only sends the first 5 characters to the API.
3. **Network**: Some API calls require internet access.
4. **Log Permissions**: Ensure you have proper permissions to read SSH logs (may require sudo).

## Troubleshooting

### "config.ini not found"

Create the configuration file:

```bash
cp config.example.ini config.ini
```

### "API Key not set"

Edit `config.ini` and add your VirusTotal API key:

```ini
[API_KEYS]
avScanner = YOUR_KEY_HERE
```

### Docker container exits immediately

Use `docker-compose run --rm toolkit` instead of `docker-compose up` for interactive mode.

### "Permission denied" on log files

Ensure you have read permissions on the log file or run with appropriate privileges:

```bash
sudo python sec-tool.py --analyze-logs /var/log/auth.log
```

### API rate limit exceeded

Wait before making additional requests, or upgrade your API tier for higher limits.

## Individual Tools

Each security tool can also be run as a standalone script. Individual versions of each tool are available in the `Tools/` folder:

- **check-leaked-pass.py** - Standalone password leak checker
- **check-av-files.py** - Standalone antivirus file scanner
- **log-analyzer-basic.py** - Standalone SSH log analyzer
- **secure-pass-tkinter.py** - Tkinter GUI for secure password generation
- **test.py** - Testing utilities

These can be run independently or imported as modules:

```bash
python Tools/check-leaked-pass.py "password"
python Tools/check-av-files.py /path/to/file
python Tools/log-analyzer-basic.py /var/log/auth.log
python Tools/secure-pass-tkinter.py
```

## File Structure

```
SecurityToolKit Python/
├── README.md                 # This file
├── DOCKER_README.md         # Detailed Docker documentation
├── Dockerfile               # Container definition
├── docker-compose.yml       # Docker Compose orchestration
├── requirements.txt         # Python dependencies
├── config.example.ini       # Configuration template
├── config.ini              # Actual configuration (created from template)
├── sec-tool.py             # Main toolkit application
├── Tools/                  # Individual tool scripts
│   ├── check-leaked-pass.py       # Standalone password checker
│   ├── check-av-files.py          # Standalone AV scanner
│   ├── log-analyzer-basic.py      # Standalone log analyzer
│   ├── secure-pass-tkinter.py     # Password generator with GUI
│   └── test.py                    # Testing utilities
├── auth_sample.log         # Sample SSH log
└── auth_real.log           # Real SSH log example
```

## Development

To modify or extend the toolkit:

1. **Main toolkit**: Edit `sec-tool.py` for core functionality and integrated features
2. **Individual tools**: Add or modify scripts in the `Tools/` folder for standalone functionality
3. **Configuration**: Update `config.example.ini` for new configuration options
4. **Dependencies**: Update `requirements.txt` if adding new dependencies
5. **Docker**: Rebuild Docker image: `docker build -t security-toolkit:latest .`
6. **Testing**: Use `Tools/test.py` for testing individual components

## License

Created by Eduardo Nobre

## Contributing

Contributions welcome! Please:

1. Test changes locally
2. Update documentation
3. Ensure API keys are not committed to version control
4. Use `.gitignore` to exclude config.ini

## Support

For issues or questions:

1. Check the Troubleshooting section
2. Review `DOCKER_README.md` for Docker-specific issues
3. Verify API keys and permissions
4. Check internet connectivity for API calls

## Related Projects

- **threat-defense-system**: Comprehensive threat detection and response system
- Part of the SecurityToolKit ecosystem

## References

- VirusTotal: https://www.virustotal.com
- Pwned Passwords: https://haveibeenpwned.com
- IP API: https://ip-api.com
