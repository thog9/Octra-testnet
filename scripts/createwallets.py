import os
import time
import base64
import hashlib
import hmac
import base58
import asyncio
from mnemonic import Mnemonic
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Border width
BORDER_WIDTH = 80

# Bilingual vocabulary
LANG = {
    'vi': {
        'title': 'TẠO VÍ MỚI - OCTRA WALLET',
        'input_count': 'Nhập số lượng ví muốn tạo (mặc định 1): ',
        'invalid_input': 'Đầu vào không hợp lệ, sử dụng giá trị mặc định: 1',
        'generating_entropy': 'Đang tạo entropy cho ví {index}...',
        'entropy_generated': 'Đã tạo entropy cho ví {index}',
        'creating_mnemonic': 'Đang tạo cụm từ khôi phục cho ví {index}...',
        'mnemonic_created': 'Đã tạo cụm từ khôi phục cho ví {index}',
        'deriving_seed': 'Đang tạo seed từ cụm từ khôi phục cho ví {index}...',
        'seed_derived': 'Đã tạo seed cho ví {index}',
        'deriving_master_key': 'Đang tạo master key cho ví {index}...',
        'master_key_derived': 'Đã tạo master key cho ví {index}',
        'creating_keypair': 'Đang tạo cặp khóa Ed25519 cho ví {index}...',
        'keypair_created': 'Đã tạo cặp khóa cho ví {index}',
        'generating_address': 'Đang tạo địa chỉ Octra cho ví {index}...',
        'address_generated': 'Đã tạo và xác minh địa chỉ cho ví {index}',
        'testing_signature': 'Đang kiểm tra chức năng chữ ký cho ví {index}...',
        'signature_test_passed': 'Kiểm tra chữ ký thành công cho ví {index}',
        'signature_test_failed': 'Kiểm tra chữ ký thất bại cho ví {index}',
        'saving_wallet': 'Đang lưu thông tin ví {index} vào wallets.txt...',
        'wallet_saved': 'Đã lưu ví {index} vào {filename}',
        'completed': '🏁 HOÀN THÀNH: ĐÃ TẠO {count} VÍ THÀNH CÔNG',
        'error': 'Lỗi với ví {index}: {error}',
        'security_warning': 'CẢNH BÁO BẢO MẬT: GIỮ FILE NÀY AN TOÀN VÀ KHÔNG CHIA SẺ KHÓA RIÊNG',
    },
    'en': {
        'title': 'NEW WALLET GENERATION - OCTRA WALLET',
        'input_count': 'Enter the number of wallets to create (default 1): ',
        'invalid_input': 'Invalid input, using default value: 1',
        'generating_entropy': 'Generating entropy for wallet {index}...',
        'entropy_generated': 'Entropy generated for wallet {index}',
        'creating_mnemonic': 'Creating mnemonic phrase for wallet {index}...',
        'mnemonic_created': 'Mnemonic created for wallet {index}',
        'deriving_seed': 'Deriving seed from mnemonic for wallet {index}...',
        'seed_derived': 'Seed derived for wallet {index}',
        'deriving_master_key': 'Deriving master key for wallet {index}...',
        'master_key_derived': 'Master key derived for wallet {index}',
        'creating_keypair': 'Creating Ed25519 keypair for wallet {index}...',
        'keypair_created': 'Keypair created for wallet {index}',
        'generating_address': 'Generating Octra address for wallet {index}...',
        'address_generated': 'Address generated and verified for wallet {index}',
        'testing_signature': 'Testing signature functionality for wallet {index}...',
        'signature_test_passed': 'Signature test passed for wallet {index}',
        'signature_test_failed': 'Signature test failed for wallet {index}',
        'saving_wallet': 'Saving wallet {index} info to wallets.txt...',
        'wallet_saved': 'Wallet {index} saved to {filename}',
        'completed': '🏁 COMPLETED: {count} WALLETS GENERATED SUCCESSFULLY',
        'error': 'Error with wallet {index}: {error}',
        'security_warning': 'SECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEY',
    }
}

# Display functions
def print_border(text: str, color=Fore.CYAN, width=BORDER_WIDTH):
    text = text.strip()
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(message: str, color=Fore.YELLOW):
    print(f"{color}  > {message}{Style.RESET_ALL}")

# Helper functions
def buffer_to_hex(buffer: bytes) -> str:
    return buffer.hex()

def base64_encode(buffer: bytes) -> str:
    return base64.b64encode(buffer).decode('utf-8')

def base58_encode(buffer: bytes) -> str:
    return base58.b58encode(buffer).decode('utf-8')

def generate_entropy(strength: int = 128) -> bytes:
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError("Strength must be 128, 160, 192, 224 or 256 bits")
    return os.urandom(strength // 8)

def derive_master_key(seed: bytes) -> tuple[bytes, bytes]:
    key = b"Octra seed"
    mac = hmac.new(key, seed, hashlib.sha512).digest()
    master_private_key = mac[:32]
    master_chain_code = mac[32:64]
    return master_private_key, master_chain_code

def create_octra_address(public_key: bytes) -> str:
    hash = hashlib.sha256(public_key).digest()
    base58_hash = base58_encode(hash)
    return "oct" + base58_hash

def verify_address_format(address: str) -> bool:
    if not address.startswith("oct") or len(address) != 47:
        return False
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_part = address[3:]
    return all(char in base58_alphabet for char in base58_part)

async def generate_wallet(index: int, language: str = 'en') -> dict:
    try:
        print_separator()  # Separator for each wallet
        print_message(f"Wallet {index}", Fore.CYAN)

        # Step 1: Generate entropy
        print_message(LANG[language]['generating_entropy'].format(index=index), Fore.CYAN)
        entropy = generate_entropy(128)
        await asyncio.sleep(0.2)
        print_message(LANG[language]['entropy_generated'].format(index=index), Fore.GREEN)

        # Step 2: Create mnemonic
        print_message(LANG[language]['creating_mnemonic'].format(index=index), Fore.CYAN)
        mnemo = Mnemonic("english")  # Use English for mnemonic wordlist
        mnemonic = mnemo.generate(strength=128)
        mnemonic_words = mnemonic.split()
        await asyncio.sleep(0.2)
        print_message(LANG[language]['mnemonic_created'].format(index=index), Fore.GREEN)

        # Step 3: Derive seed
        print_message(LANG[language]['deriving_seed'].format(index=index), Fore.CYAN)
        seed = mnemo.to_seed(mnemonic)
        await asyncio.sleep(0.2)
        print_message(LANG[language]['seed_derived'].format(index=index), Fore.GREEN)

        # Step 4: Derive master key
        print_message(LANG[language]['deriving_master_key'].format(index=index), Fore.CYAN)
        master_private_key, master_chain_code = derive_master_key(seed)
        await asyncio.sleep(0.2)
        print_message(LANG[language]['master_key_derived'].format(index=index), Fore.GREEN)

        # Step 5: Create Ed25519 keypair
        print_message(LANG[language]['creating_keypair'].format(index=index), Fore.CYAN)
        signing_key = SigningKey(master_private_key, encoder=RawEncoder)
        private_key = signing_key.encode()
        public_key = signing_key.verify_key.encode()
        await asyncio.sleep(0.2)
        print_message(LANG[language]['keypair_created'].format(index=index), Fore.GREEN)

        # Step 6: Generate Octra address
        print_message(LANG[language]['generating_address'].format(index=index), Fore.CYAN)
        address = create_octra_address(public_key)
        if not verify_address_format(address):
            raise ValueError("Invalid address format generated")
        await asyncio.sleep(0.2)
        print_message(LANG[language]['address_generated'].format(index=index), Fore.GREEN)

        # Step 7: Test signature
        print_message(LANG[language]['testing_signature'].format(index=index), Fore.CYAN)
        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        message_bytes = test_message.encode('utf-8')
        signature = signing_key.sign(message_bytes, encoder=RawEncoder).signature
        signature_b64 = base64_encode(signature)
        signature_valid = VerifyKey(public_key, encoder=RawEncoder).verify(message_bytes, signature, encoder=RawEncoder)
        await asyncio.sleep(0.2)
        print_message(
            LANG[language]['signature_test_passed'].format(index=index) if signature_valid else LANG[language]['signature_test_failed'].format(index=index),
            Fore.GREEN if signature_valid else Fore.RED
        )

        # Step 8: Prepare wallet data
        wallet_data = {
            'mnemonic': mnemonic_words,
            'seed_hex': buffer_to_hex(seed),
            'master_chain_hex': buffer_to_hex(master_chain_code),
            'private_key_hex': buffer_to_hex(private_key),
            'public_key_hex': buffer_to_hex(public_key),
            'private_key_b64': base64_encode(private_key),
            'public_key_b64': base64_encode(public_key),
            'address': address,
            'entropy_hex': buffer_to_hex(entropy),
            'test_message': test_message,
            'test_signature': signature_b64,
            'signature_valid': signature_valid
        }

        # Step 9: Save to wallets.txt
        print_message(LANG[language]['saving_wallet'].format(index=index), Fore.CYAN)
        filename = "wallets.txt"
        content = f"""OCTRA WALLET {index}
{'=' * 50}

{LANG[language]['security_warning']}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Address Format: oct + Base58(SHA256(pubkey))

Mnemonic: {' '.join(wallet_data['mnemonic'])}
Private Key (Hex): {wallet_data['private_key_hex']}
Private Key (B64): {wallet_data['private_key_b64']}
Public Key (Hex): {wallet_data['public_key_hex']}
Public Key (B64): {wallet_data['public_key_b64']}
Address: {wallet_data['address']}

Technical Details:
Entropy: {wallet_data['entropy_hex']}
Seed: {wallet_data['seed_hex']}
Master Chain Code: {wallet_data['master_chain_hex']}
Signature Algorithm: Ed25519
Test Message: {wallet_data['test_message']}
Test Signature (B64): {wallet_data['test_signature']}
Signature Valid: {wallet_data['signature_valid']}
{'=' * 50}

"""
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(content)
        await asyncio.sleep(0.2)
        print_message(LANG[language]['wallet_saved'].format(index=index, filename=filename), Fore.GREEN)

        return wallet_data

    except Exception as e:
        print_message(LANG[language]['error'].format(index=index, error=str(e)), Fore.RED)
        raise

async def generate_multiple_wallets(count: int, language: str = 'en'):
    # Semaphore to limit concurrent tasks (similar to checkin.py)
    semaphore = asyncio.Semaphore(2)  # Limit to 2 concurrent wallet generations
    successful_wallets = 0

    async def process_wallet(index):
        nonlocal successful_wallets
        async with semaphore:
            try:
                await generate_wallet(index, language)
                successful_wallets += 1
            except Exception:
                pass  # Errors are handled within generate_wallet

    tasks = [process_wallet(i + 1) for i in range(count)]
    await asyncio.gather(*tasks, return_exceptions=True)

    print()
    print_border(LANG[language]['completed'].format(count=successful_wallets), Fore.GREEN)
    print()

def get_wallet_count(language: str = 'en') -> int:
    try:
        print(f"{Fore.CYAN}  > {LANG[language]['input_count']}{Style.RESET_ALL}", end='')
        count = input().strip()
        return int(count) if count else 1
    except ValueError:
        print_message(LANG[language]['invalid_input'], Fore.YELLOW)
        return 1

async def run_createwallets(language: str = 'en'):
    print_border(LANG[language]['title'], Fore.CYAN)
    print()
    count = get_wallet_count(language)
    await generate_multiple_wallets(count, language)

if __name__ == "__main__":
    asyncio.run(run_createwallets('vi'))  # Use Vietnamese language
