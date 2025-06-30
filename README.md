# Octra Testnet Bot 🚀

Octra Bot is a powerful Python tool providing a command-line interface (CLI) to automate tasks on the Octra Testnet. From wallet creation to sending transactions and claiming testnet tokens from the faucet, Octra Bot streamlines your workflow with a bilingual (English/Vietnamese) menu, proxy support, and a vibrant CLI. Save time and maximize rewards!

🔗 Octra Faucet: [Octra Faucet](https://faucet.octra.network)

## ✨ Features Overview

### General Features

- **Multi-Account Support**: Processes multiple accounts using tokens from `pvkey.txt`.
- **Colorful CLI**: Uses `colorama` for visually appealing output with colored text and borders.
- **Proxy Support**: Supports HTTP, HTTPS, SOCKS4, and SOCKS5 proxies via `proxies.txt`.
- **Asynchronous Execution**: Built with `asyncio` for efficient blockchain interactions.
- **Error Handling**: Comprehensive error catching for blockchain transactions and RPC issues.
- **Bilingual Support**: Supports both English and Vietnamese output based on user selection.

### Included Scripts

1. **Octra Wallet Creation**: Generates new wallets for the Octra Testnet, securely storing private keys.
2. **Send Transaction (Send TX)**: Automates transaction sending on the Octra Testnet.
3. **Faucet Octra**: Claims testnet tokens from `https://faucet.octra.network` with:
   - Multi-address support from `addressFaucet.txt`.
   - Automatic reCAPTCHA solving via 2captcha.
   - Proxy support (HTTP/HTTPS/SOCKS4/SOCKS5) from `proxies.txt`.
   - Concurrent processing with up to 9 threads.
4. **Exit**: Gracefully exits the program with a friendly message.

## 🛠️ Prerequisites

Before running the scripts, ensure you have the following installed:

- Python 3.8+
- `pip` (Python package manager)
- **Dependencies**: Install via `pip install -r requirements.txt` (ensure `web3.py`, `colorama`, `asyncio`, `eth-account`, `aiohttp_socks` and `inquirer` are included).
- **pvkey.txt**: Add private keys (one per line) for wallet automation.
- **address.txt**: (optional): Optional files for specifying recipient addresses.
- **addressFaucet.txt** (for Faucet): Add Octra addresses (one per line).
- **proxies.txt** (optional): Add proxy addresses for network requests, if needed.

## 📦 Installation

1. **Clone this repository:**
- Open cmd or Shell, then run the command:
```sh
git clone https://github.com/thog9/Octra-testnet.git
```
```sh
cd Octra-testnet
```
2. **Install Dependencies:**
- Open cmd or Shell, then run the command:
```sh
pip install -r requirements.txt
```
3. **Prepare Input Files:**
- Open the `pvkey.txt`: Add your private keys (one per line) in the root directory.
```sh
nano pvkey.txt 
```
- Create `address.txt`, `proxies.txt`, `addressFaucet.txt` for specific operations:
```sh
nano address.txt
nano proxies.txt
addressFaucet.txt
```
- **2captchakey.txt** (optional, for Faucet): Add your 2captcha API key. If missing, the bot will prompt for input.
- **2captcha Account**: Sign up at [2captcha.com](https://2captcha.com) and ensure sufficient balance (for Faucet).
```sh
nano 2captchakey.txt
```
4. **Run:**
- Open cmd or Shell, then run command:
```sh
python main.py
```
- Choose a language (Vietnamese/English).

## 📬 Contact
Connect with us for support or updates:

- **Telegram**: [thog099](https://t.me/thog099)
- **Channel**: [CHANNEL](https://t.me/thogairdrops)
- **Group**: [GROUP CHAT](https://t.me/thogchats)
- **X**: [Thog](https://x.com/thog099) 

----

## ☕ Support Us
Love these scripts? Fuel our work with a coffee!

🔗 BUYMECAFE: [BUY ME CAFE](https://buymecafe.vercel.app/)
