import os
import sys
import asyncio
import random
import time
import json
import base64
import hashlib
import re
from typing import List, Tuple, Optional, Dict, Any
from colorama import init, Fore, Style
import aiohttp
from aiohttp_socks import ProxyConnector
from nacl.signing import SigningKey
import base58

# Initialize colorama
init(autoreset=True)

# Border width
BORDER_WIDTH = 80

# Constants
NETWORK_URL = "https://octra.network"
EXPLORER_URL = "https://octrascan.io/tx/"
SYMBOL = "OCT"
MICRO_UNIT = 1_000_000
ADDRESS_REGEX = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")
AMOUNT_REGEX = re.compile(r"^\d+(\.\d+)?$")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
}
CONFIG = {
    "PAUSE_BETWEEN_ATTEMPTS": [10, 30],
    "MAX_CONCURRENCY": 5,
    "MAX_RETRIES": 3,
    "MINIMUM_BALANCE": 0.001,  
    "DELAY_BETWEEN_ACCOUNTS": 5,  
    "RETRY_DELAY": 3,  
    "TIMEOUT": 30,  
}

# Bilingual vocabulary
LANG = {
    'vi': {
        'title': '✨ GỬI GIAO DỊCH - MẠNG OCTRA ✨',
        'info': 'ℹ Thông tin',
        'found': 'Tìm thấy',
        'wallets': 'ví',
        'processing_wallets': '⚙ Đang xử lý {count} ví',
        'found_proxies': 'Tìm thấy {count} proxy trong proxies.txt',
        'enter_tx_count': '✦ NHẬP SỐ LƯỢNG GIAO DỊCH',
        'tx_count_prompt': 'Số lượng giao dịch (mặc định 1): ',
        'selected': 'Đã chọn',
        'transactions': 'giao dịch',
        'enter_amount': '✦ NHẬP SỐ LƯỢNG OCT',
        'amount_prompt': 'Số lượng OCT (mặc định 0.000001, tối đa 999): ',
        'amount_unit': 'OCT',
        'select_tx_type': '✦ CHỌN LOẠI GIAO DỊCH',
        'random_option': '1. Gửi đến địa chỉ ngẫu nhiên',
        'file_option': '2. Gửi đến các địa chỉ từ file (address.txt)',
        'choice_prompt': 'Nhập lựa chọn (1 hoặc 2): ',
        'start_random': '✨ BẮT ĐẦU {tx_count} GIAO DỊCH NGẪU NHIÊN',
        'start_file': '✨ BẮT ĐẦU GIAO DỊCH TỚI {addr_count} ĐỊA CHỈ TỪ FILE',
        'processing_wallet': '⚙ Đang xử lý ví',
        'checking_balance': 'Đang kiểm tra số dư...',
        'insufficient_balance': 'Số dư không đủ (cần ít nhất {required:.6f} OCT cho giao dịch)',
        'transaction': 'Giao dịch',
        'to_address': 'Địa chỉ nhận',
        'sending': 'Đang gửi giao dịch...',
        'success': '✅ Giao dịch thành công!',
        'failure': '❌ Giao dịch thất bại',
        'timeout': '⏰ Giao dịch không được xác nhận sau {timeout} giây, kiểm tra trên explorer',
        'sender': 'Người gửi',
        'receiver': 'Người nhận',
        'amount': 'Số lượng',
        'fee': 'Phí',
        'hash': 'Hash',
        'pausing': 'Tạm dừng',
        'seconds': 'giây',
        'completed': '🏁 HOÀN THÀNH: {successful}/{total} GIAO DỊCH THÀNH CÔNG',
        'error': 'Lỗi',
        'invalid_number': 'Vui lòng nhập một số hợp lệ',
        'tx_count_error': 'Số lượng giao dịch phải lớn hơn 0',
        'amount_error': 'Số lượng phải lớn hơn 0 và không vượt quá 999',
        'invalid_choice': 'Lựa chọn không hợp lệ',
        'connect_error': '❌ Không thể kết nối tới RPC',
        'pvkey_not_found': '❌ Không tìm thấy file pvkey.txt',
        'pvkey_empty': '❌ Không tìm thấy khóa riêng tư hợp lệ',
        'pvkey_error': '❌ Không thể đọc pvkey.txt',
        'addr_not_found': '❌ Không tìm thấy file address.txt',
        'addr_empty': '❌ Không tìm thấy địa chỉ hợp lệ trong address.txt',
        'addr_error': '❌ Không thể đọc address.txt',
        'invalid_addr': 'không phải là địa chỉ hợp lệ, đã bỏ qua',
        'warning_line': '⚠ Cảnh báo: Dòng',
        'using_proxy': '🔄 🔄 Using Proxy - [{proxy}] with Public IP - [{public_ip}]',
        'no_proxy': 'Không có',
        'unknown': 'Không xác định',
        'no_proxies': 'Không tìm thấy proxy trong proxies.txt',
        'invalid_proxy': '⚠ Proxy không hợp lệ hoặc không phản hồi: {proxy}',
        'ip_check_failed': '⚠ Không thể kiểm tra IP công khai: {error}',
        'balance_info': 'Số dư ví',
    }
}

# Display functions
def print_border(text: str, color=Fore.CYAN, width=BORDER_WIDTH, language: str = 'vi'):
    text = text.strip()
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(message: str, color=Fore.YELLOW, language: str = 'vi'):
    print(f"{color}{message}{Style.RESET_ALL}")

def print_wallets_summary(count: int, language: str = 'vi'):
    print_border(
        LANG[language]['processing_wallets'].format(count=count),
        Fore.MAGENTA, language=language
    )
    print()

def display_wallet_balance(address: str, balance: float, language: str = 'vi'):
    print_border(LANG[language]['balance_info'], Fore.CYAN, language=language)
    print(f"{Fore.CYAN}  Địa chỉ: {address}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Số dư: {balance:.6f} {SYMBOL}{Style.RESET_ALL}")
    print()

# Utility functions
def is_valid_private_key_b64(key: str) -> bool:
    try:
        decoded = base64.b64decode(key)
        return len(decoded) == 32  # Ed25519 private key length
    except:
        return False

def create_octra_address(public_key: bytes) -> str:
    hash = hashlib.sha256(public_key).digest()
    base58_hash = base58.b58encode(hash).decode('utf-8')
    return "oct" + base58_hash

def load_private_keys(file_path: str = "pvkey.txt", language: str = 'vi') -> List[Tuple[int, str, str]]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_not_found']}{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add private keys (Base64) here, one per line\n# Example: EjRWeJ0a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t=\n")
            sys.exit(1)
        
        valid_keys = []
        with open(file_path, 'r') as f:
            for i, line in enumerate(f, 1):
                key = line.strip()
                if key and not key.startswith('#'):
                    if is_valid_private_key_b64(key):
                        try:
                            signing_key = SigningKey(base64.b64decode(key))
                            address = create_octra_address(signing_key.verify_key.encode())
                            if not ADDRESS_REGEX.match(address):
                                print(f"{Fore.YELLOW}  ⚠ {LANG[language]['warning_line']} {i}: Invalid address format: {address}{Style.RESET_ALL}")
                                continue
                            valid_keys.append((i, key, address))
                        except Exception as e:
                            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['warning_line']} {i}: Error deriving address: {str(e)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['warning_line']} {i}: Invalid private key (B64): {key}{Style.RESET_ALL}")
        
        if not valid_keys:
            print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_empty']}{Style.RESET_ALL}")
            sys.exit(1)
        
        return valid_keys
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['pvkey_error']}: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def load_addresses(file_path: str = "address.txt", language: str = 'vi') -> Optional[List[str]]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['addr_not_found']}. Creating new file.{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add recipient addresses here, one per line\n# Example: oct1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t\n")
            return None
        
        addresses = []
        with open(file_path, 'r') as f:
            for i, line in enumerate(f, 1):
                addr = line.strip()
                if addr and not addr.startswith('#'):
                    if ADDRESS_REGEX.match(addr):
                        addresses.append(addr)
                    else:
                        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['warning_line']} {i}: {LANG[language]['invalid_addr']} - {addr}{Style.RESET_ALL}")
        
        if not addresses:
            print(f"{Fore.RED}  ✖ {LANG[language]['addr_empty']}{Style.RESET_ALL}")
            return None
        
        return addresses
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['addr_error']}: {str(e)}{Style.RESET_ALL}")
        return None

async def load_proxies(file_path: str = "proxies.txt", language: str = 'vi') -> List[str]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add proxies here, one per line\n# Example: socks5://user:pass@host:port or http://host:port or user:pass@host:port\n")
            return []
        
        proxies = []
        with open(file_path, 'r') as f:
            for line in f:
                proxy = line.strip()
                if proxy and not line.startswith('#'):
                    # Handle different proxy formats
                    if proxy.startswith(('socks5://', 'socks4://', 'http://', 'https://')):
                        proxy_url = proxy
                    elif ':' in proxy and '@' in proxy:
                        # Format: user:pass@host:port
                        proxy_url = f"socks5://{proxy}"
                    elif len(proxy.split(':')) == 4:
                        # Format: host:port:user:pass
                        host, port, user, passw = proxy.split(':')
                        proxy_url = f"socks5://{user}:{passw}@{host}:{port}"
                    else:
                        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}{Style.RESET_ALL}")
                        continue
                    try:
                        # Test proxy by checking public IP
                        connector = ProxyConnector.from_url(proxy_url)
                        async with aiohttp.ClientSession(connector=connector, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as proxy_session:
                            async with proxy_session.get("https://api.ipify.org?format=json") as resp:
                                if resp.status == 200:
                                    proxies.append(proxy_url)
                                else:
                                    print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}: HTTP {resp.status}{Style.RESET_ALL}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}: {str(e)}{Style.RESET_ALL}")
                        continue
        
        if not proxies:
            print(f"{Fore.YELLOW}  ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.YELLOW}  ℹ {LANG[language]['found_proxies'].format(count=len(proxies))}{Style.RESET_ALL}")
        return proxies
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['error']}: {str(e)}{Style.RESET_ALL}")
        return []

async def get_proxy_ip(proxy: str = None, language: str = 'vi') -> str:
    try:
        if proxy:
            if proxy.startswith(('socks5://', 'socks4://', 'http://', 'https://')):
                proxy_url = proxy
            elif ':' in proxy and '@' in proxy:
                # Format: user:pass@host:port
                proxy_url = f"socks5://{proxy}"
            elif len(proxy.split(':')) == 4:
                # Format: host:port:user:pass
                host, port, user, passw = proxy.split(':')
                proxy_url = f"socks5://{user}:{passw}@{host}:{port}"
            else:
                print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}{Style.RESET_ALL}")
                return LANG[language]['unknown']
            connector = ProxyConnector.from_url(proxy_url)
            async with aiohttp.ClientSession(connector=connector, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get("https://api.ipify.org?format=json") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('ip', LANG[language]['unknown'])
                    print(f"{Fore.YELLOW}  ⚠ {LANG[language]['ip_check_failed'].format(error=f'HTTP {resp.status}')}{Style.RESET_ALL}")
                    return LANG[language]['unknown']
        else:
            async with aiohttp.ClientSession(headers=HEADERS, timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get("https://api.ipify.org?format=json") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('ip', LANG[language]['unknown'])
                    print(f"{Fore.YELLOW}  ⚠ {LANG[language]['ip_check_failed'].format(error=f'HTTP {resp.status}')}{Style.RESET_ALL}")
                    return LANG[language]['unknown']
    except Exception as e:
        print(f"{Fore.YELLOW}  ⚠ {LANG[language]['ip_check_failed'].format(error=str(e))}{Style.RESET_ALL}")
        return LANG[language]['unknown']

async def http_request(method: str, path: str, data: Optional[Dict] = None, 
                       proxy: str = None, language: str = 'vi') -> Tuple[int, str, Optional[Dict]]:
    try:
        # Handle proxy formatting
        proxy_url = None
        if proxy:
            if proxy.startswith(('socks5://', 'socks4://', 'http://', 'https://')):
                proxy_url = proxy
            elif ':' in proxy and '@' in proxy:
                # Format: user:pass@host:port
                proxy_url = f"socks5://{proxy}"
            elif len(proxy.split(':')) == 4:
                # Format: host:port:user:pass
                host, port, user, passw = proxy.split(':')
                proxy_url = f"socks5://{user}:{passw}@{host}:{port}"
            else:
                print(f"{Fore.YELLOW}  ⚠ {LANG[language]['invalid_proxy'].format(proxy=proxy)}{Style.RESET_ALL}")
                return 0, "Invalid proxy format", None

        # Initialize ClientSession with ProxyConnector if proxy is used
        connector = ProxyConnector.from_url(proxy_url) if proxy_url else None
        async with aiohttp.ClientSession(connector=connector, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=CONFIG["TIMEOUT"])) as session:
            url = f"{NETWORK_URL}{path}"
            async with getattr(session, method.lower())(url, json=data if method == 'POST' else None) as resp:
                text = await resp.text()
                try:
                    json_data = json.loads(text) if text else None
                except json.JSONDecodeError as e:
                    print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể phân tích JSON: {str(e)} (Phản hồi: {text}){Style.RESET_ALL}")
                    json_data = None
                return resp.status, text, json_data
    except asyncio.TimeoutError:
        print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Yêu cầu hết thời gian sau {CONFIG['TIMEOUT']} giây{Style.RESET_ALL}")
        return 0, "timeout", None
    except Exception as e:
        print(f"{Fore.RED}  ✖ {LANG[language]['error']}: {str(e)}{Style.RESET_ALL}")
        return 0, str(e), None

async def get_balance(address: str, proxy: str = None, language: str = 'vi') -> Optional[float]:
    status, text, json_data = await http_request('GET', f'/balance/{address}', proxy=proxy, language=language)
    if status == 200 and json_data:
        try:
            balance = float(json_data.get('balance', 0))
            print(f"{Fore.YELLOW}  ℹ Debug: Balance from API: {balance:.6f} OCT{Style.RESET_ALL}")
            return balance
        except (ValueError, TypeError) as e:
            print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Định dạng số dư không hợp lệ: {str(e)} (JSON: {json_data}){Style.RESET_ALL}")
            return None
    elif status == 200 and text:
        try:
            balance = float(text.strip().split()[0])
            print(f"{Fore.YELLOW}  ℹ Debug: Balance from text: {balance:.6f} OCT{Style.RESET_ALL}")
            return balance
        except (ValueError, IndexError) as e:
            print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể phân tích số dư: {str(e)} (Text: {text}){Style.RESET_ALL}")
            return None
    print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể lấy số dư (Trạng thái: {status}, Phản hồi: {text}){Style.RESET_ALL}")
    return None

async def get_nonce(address: str, proxy: str = None, language: str = 'vi') -> Optional[int]:
    status, text, json_data = await http_request('GET', f'/balance/{address}', proxy=proxy, language=language)
    if status == 200 and json_data:
        try:
            nonce = int(json_data.get('nonce', 0))
            print(f"{Fore.YELLOW}  ℹ Debug: Base nonce from API: {nonce}{Style.RESET_ALL}")
            # Kiểm tra staging với retry
            for attempt in range(CONFIG["MAX_RETRIES"]):
                staging_status, _, staging_data = await http_request('GET', '/staging', proxy=proxy, language=language)
                if staging_status == 200 and staging_data:
                    our_txs = [tx for tx in staging_data.get('staged_transactions', []) if tx.get('from') == address]
                    if our_txs:
                        max_staging_nonce = max(int(tx.get('nonce', 0)) for tx in our_txs)
                        nonce = max(nonce, max_staging_nonce)
                        print(f"{Fore.YELLOW}  ℹ Debug: Adjusted nonce after staging: {nonce}{Style.RESET_ALL}")
                        return nonce
                    print(f"{Fore.YELLOW}  ℹ Debug: No pending transactions in staging{Style.RESET_ALL}")
                    return nonce
                else:
                    print(f"{Fore.YELLOW}  ⚠ Debug: Staging request failed (Attempt {attempt + 1}/{CONFIG['MAX_RETRIES']}): Status {staging_status}{Style.RESET_ALL}")
                    if attempt < CONFIG["MAX_RETRIES"] - 1:
                        await asyncio.sleep(CONFIG["RETRY_DELAY"])
            print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể kiểm tra staging, sử dụng nonce cơ bản: {nonce}{Style.RESET_ALL}")
            return nonce
        except (ValueError, TypeError) as e:
            print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể lấy nonce: {str(e)} (JSON: {json_data}){Style.RESET_ALL}")
            return None
    elif status == 200 and text:
        try:
            parts = text.strip().split()
            nonce = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            print(f"{Fore.YELLOW}  ℹ Debug: Nonce from text: {nonce}{Style.RESET_ALL}")
            return nonce
        except (ValueError, IndexError) as e:
            print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể phân tích nonce: {str(e)} (Text: {text}){Style.RESET_ALL}")
            return None
    print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Không thể lấy nonce (Trạng thái: {status}, Phản hồi: {text}){Style.RESET_ALL}")
    return None

def generate_random_address() -> str:
    base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    return 'oct' + ''.join(random.choice(base58_chars) for _ in range(44))

def create_transaction(from_address: str, to_address: str, amount: float, nonce: int, signing_key: SigningKey) -> Tuple[Dict, str]:
    tx = {
        "from": from_address,
        "to_": to_address,
        "amount": str(int(amount * MICRO_UNIT)),
        "nonce": int(nonce),
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time() + random.random() * 0.01
    }
    tx_bytes = json.dumps(tx, separators=(",", ":")).encode()
    signature = base64.b64encode(signing_key.sign(tx_bytes).signature).decode()
    public_key = base64.b64encode(signing_key.verify_key.encode()).decode()
    tx.update(signature=signature, public_key=public_key)
    tx_hash = hashlib.sha256(tx_bytes).hexdigest()
    return tx, tx_hash

async def send_transaction(tx: Dict, proxy: str = None, language: str = 'vi') -> Tuple[bool, str, float]:
    start_time = time.time()
    for attempt in range(CONFIG["MAX_RETRIES"]):
        status, text, json_data = await http_request('POST', '/send-tx', tx, proxy=proxy, language=language)
        elapsed = time.time() - start_time
        if status == 200:
            if json_data and json_data.get('status') == 'accepted':
                return True, json_data.get('tx_hash', ''), elapsed
            elif text.lower().startswith('ok'):
                return True, text.split()[-1], elapsed
        elif status == 422 and json_data and json_data.get('error') == 'Invalid nonce':
            print(f"{Fore.YELLOW}  ⚠ Debug: Invalid nonce detected, retrying with updated nonce (Attempt {attempt + 1}/{CONFIG['MAX_RETRIES']}){Style.RESET_ALL}")
            if attempt < CONFIG["MAX_RETRIES"] - 1:
                # Cập nhật nonce và thử lại
                new_nonce = await get_nonce(tx['from'], proxy, language)
                if new_nonce is not None:
                    tx['nonce'] = int(new_nonce) + 1
                    tx['timestamp'] = time.time() + random.random() * 0.01
                    # Tái ký giao dịch
                    tx_bytes = json.dumps({k: v for k, v in tx.items() if k not in ['signature', 'public_key']}, separators=(",", ":")).encode()
                    signing_key = SigningKey(base64.b64decode([pk for _, pk, addr in load_private_keys() if addr == tx['from']][0]))
                    signature = base64.b64encode(signing_key.sign(tx_bytes).signature).decode()
                    tx.update(signature=signature, public_key=base64.b64encode(signing_key.verify_key.encode()).decode())
                    await asyncio.sleep(CONFIG["RETRY_DELAY"])
                    continue
        print(f"{Fore.RED}  ✖ {LANG[language]['error']}: Giao dịch thất bại (Trạng thái: {status}, Phản hồi: {text}){Style.RESET_ALL}")
        return False, json.dumps(json_data) if json_data else text, elapsed
    return False, "Max retries reached", elapsed

async def process_wallet(profile_num: int, private_key_b64: str, address: str, tx_count: int, amount: float, 
                        addresses: Optional[List[str]], semaphore: asyncio.Semaphore, 
                        proxies: List[str], language: str = 'vi') -> Tuple[int, int]:
    async with semaphore:
        try:
            signing_key = SigningKey(base64.b64decode(private_key_b64))
            
            proxy = random.choice(proxies) if proxies else None
            proxy_display = proxy if proxy else LANG[language]['no_proxy']
            if proxy:
                if proxy.startswith(('socks5://', 'socks4://', 'http://', 'https://')):
                    proxy_display = proxy.replace('socks5://', 'http://')  # Display as http:// for consistency
                elif ':' in proxy and '@' in proxy:
                    proxy_display = proxy
                elif len(proxy.split(':')) == 4:
                    host, port, user, passw = proxy.split(':')
                    proxy_display = f"{user}:{passw}@{host}:{port}"
            public_ip = await get_proxy_ip(proxy, language)
            print(f"{Fore.CYAN}  {LANG[language]['using_proxy'].format(proxy=proxy_display, public_ip=public_ip)}{Style.RESET_ALL}")
            
            print_border(f"{LANG[language]['processing_wallet']} {profile_num} - {address}", Fore.MAGENTA, language=language)
            print_message(LANG[language]['checking_balance'], Fore.YELLOW, language)
            
            balance = await get_balance(address, proxy, language)
            if balance is None:
                print_message(f"{Fore.RED}  ✖ Lỗi: Không thể lấy số dư, bỏ qua ví {profile_num}{Style.RESET_ALL}")
                return 0, 0
            
            required_balance = amount * tx_count + (0.001 if amount < 1000 else 0.003) * tx_count
            total_required = required_balance + CONFIG["MINIMUM_BALANCE"]
            print(f"{Fore.YELLOW}  ℹ Debug: Số dư: {balance:.6f} OCT, Cần: {total_required:.6f} OCT (amount={amount}, tx_count={tx_count}, fee={0.001 if amount < 1000 else 0.003}){Style.RESET_ALL}")
            if balance < total_required:
                print_message(
                    LANG[language]['insufficient_balance'].format(required=total_required),
                    Fore.RED, language
                )
                return 0, 0
            
            display_wallet_balance(address, balance, language)
            nonce = await get_nonce(address, proxy, language)
            if nonce is None:
                print_message(f"{Fore.RED}  ✖ Lỗi: Không thể lấy nonce, bỏ qua ví {profile_num}{Style.RESET_ALL}")
                return 0, 0
            
            successful_txs = 0
            total_txs = tx_count if addresses is None else len(addresses)
            
            for i in range(total_txs):
                to_address = generate_random_address() if addresses is None else addresses[i % len(addresses)]
                print_message(
                    f"{LANG[language]['transaction']} {i + 1}/{total_txs} - {LANG[language]['to_address']}: {to_address}",
                    Fore.YELLOW, language
                )
                
                for attempt in range(CONFIG["MAX_RETRIES"]):
                    try:
                        print_message(LANG[language]['sending'], Fore.YELLOW, language)
                        tx, tx_hash = create_transaction(address, to_address, amount, nonce + i, signing_key)
                        success, result, elapsed = await send_transaction(tx, proxy, language)
                        
                        if success:
                            print_message(f"{LANG[language]['success']} Hash: {EXPLORER_URL}{result}", Fore.GREEN, language)
                            print_message(
                                f"{LANG[language]['sender']}: {address}\n"
                                f"{LANG[language]['receiver']}: {to_address}\n"
                                f"{LANG[language]['amount']}: {amount:.6f} {SYMBOL}\n"
                                f"{LANG[language]['fee']}: {'0.001' if amount < 1000 else '0.003'} {SYMBOL}\n"
                                f"{LANG[language]['hash']}: {result}",
                                Fore.CYAN, language
                            )
                            successful_txs += 1
                            break
                        else:
                            print_message(f"{LANG[language]['failure']}: {result}", Fore.RED, language)
                            if attempt < CONFIG["MAX_RETRIES"] - 1:
                                print_message(
                                    f"Thử lại sau {CONFIG['RETRY_DELAY']} {LANG[language]['seconds']}...",
                                    Fore.YELLOW, language
                                )
                                await asyncio.sleep(CONFIG["RETRY_DELAY"])
                    except Exception as e:
                        print_message(f"{LANG[language]['error']}: {str(e)}", Fore.RED, language)
                        if attempt < CONFIG["MAX_RETRIES"] - 1:
                            print_message(
                                f"Thử lại sau {CONFIG['RETRY_DELAY']} {LANG[language]['seconds']}...",
                                Fore.YELLOW, language
                            )
                            await asyncio.sleep(CONFIG["RETRY_DELAY"])
                
                if i < total_txs - 1:
                    pause = random.uniform(*CONFIG["PAUSE_BETWEEN_ATTEMPTS"])
                    print_message(
                        f"{LANG[language]['pausing']} {pause:.2f} {LANG[language]['seconds']}...",
                        Fore.YELLOW, language
                    )
                    await asyncio.sleep(pause)
            
            return successful_txs, total_txs
        except Exception as e:
            print_message(f"{LANG[language]['error']}: {str(e)}", Fore.RED, language)
            return 0, 0

async def run_sendtx(language: str = 'en'):
    language = 'vi'
    print_border(LANG[language]['title'], Fore.CYAN, language=language)
    
    # Load private keys
    private_keys = load_private_keys(language=language)
    print_wallets_summary(len(private_keys), language)
    
    # Load proxies
    proxies = await load_proxies(language=language)
    
    # Get transaction count
    print_border(LANG[language]['enter_tx_count'], Fore.CYAN, language=language)
    try:
        tx_count_input = input(f"{Fore.YELLOW}{LANG[language]['tx_count_prompt']}{Style.RESET_ALL}")
        tx_count = int(tx_count_input) if tx_count_input.strip() else 1
        if tx_count <= 0:
            raise ValueError
    except ValueError:
        print_message(LANG[language]['tx_count_error'], Fore.RED, language)
        return
    
    print_message(f"{LANG[language]['selected']} {tx_count} {LANG[language]['transactions']}", Fore.GREEN, language)
    
    # Get amount
    print_border(LANG[language]['enter_amount'], Fore.CYAN, language=language)
    try:
        amount_input = input(f"{Fore.YELLOW}{LANG[language]['amount_prompt']}{Style.RESET_ALL}")
        amount = float(amount_input) if amount_input.strip() else 0.000001
        if amount <= 0 or amount > 999:
            raise ValueError
    except ValueError:
        print_message(LANG[language]['amount_error'], Fore.RED, language)
        return
    
    print_message(f"{LANG[language]['selected']} {amount:.6f} {LANG[language]['amount_unit']}", Fore.GREEN, language)
    
    # Select transaction type
    print_border(LANG[language]['select_tx_type'], Fore.CYAN, language=language)
    print_message(f"{LANG[language]['random_option']}", Fore.YELLOW, language)
    print_message(f"{LANG[language]['file_option']}", Fore.YELLOW, language)
    choice = input(f"{Fore.YELLOW}{LANG[language]['choice_prompt']}{Style.RESET_ALL}").strip()
    
    addresses = None
    if choice == '2':
        addresses = load_addresses(language=language)
        if not addresses:
            return
        print_border(LANG[language]['start_file'].format(addr_count=len(addresses)), Fore.CYAN, language=language)
    elif choice == '1':
        print_border(LANG[language]['start_random'].format(tx_count=tx_count), Fore.CYAN, language=language)
    else:
        print_message(LANG[language]['invalid_choice'], Fore.RED, language)
        return
    
    # Process wallets concurrently
    semaphore = asyncio.Semaphore(CONFIG["MAX_CONCURRENCY"])
    tasks = [
        process_wallet(profile_num, private_key_b64, address, tx_count, amount, addresses, semaphore, proxies, language)
        for profile_num, private_key_b64, address in private_keys
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Summarize results
    total_successful = sum(r[0] for r in results if not isinstance(r, Exception))
    total_txs = sum(r[1] for r in results if not isinstance(r, Exception))
    print_border(
        LANG[language]['completed'].format(successful=total_successful, total=total_txs),
        Fore.CYAN, language=language
    )

if __name__ == "__main__":
    asyncio.run(run_sendtx('vi'))
