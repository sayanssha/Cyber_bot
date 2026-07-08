# Cyber_bot
Ultra-fast, dependency-free static code scanner to detect exposed API keys and secrets.
# Cyber-Protect Bot 🛡️

`cyber-protect-bot` is an ultra-fast, dependency-free static code scanner built to discover exposed API keys, private tokens, and credentials hidden within your source code before they leak online. 

Designed for both developer machines and automated CI/CD pipelines.

## Quick Start

```bash
# Clone the repository
git clone [https://github.com/sayanssha/cyber-protect-bot.git](https://github.com/YOUR_GITHUB_USERNAME/cyber-protect-bot.git)
cd cyber-protect-bot

# Run a scan on any directory
python3 cyber_protect_bot.py -p /path/to/your/project
