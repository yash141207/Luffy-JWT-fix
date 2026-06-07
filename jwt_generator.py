#!/usr/bin/env python3
"""
Generate JWT from Access Token using Garena official endpoints.
Works on Termux (no external APIs except Garena).
Supports single token, JSON file, and UID:PASS file inputs.
WITH THREADING SUPPORT & SMART DEDUPLICATION
"""

import requests
import binascii
import jwt
import time
import random
import json
import os
import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from datetime import datetime
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== GET SCRIPT DIRECTORY ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== CONSTANTS ====================
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
GARENA_LOGIN_URL = "https://account.garena.com/api/login"
FREEFIRE_VERSION = "OB53"

KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
}

# Thread-safe storage for results
results_lock = threading.Lock()
token_cache = {}  # Cache for token -> result
token_cache_lock = threading.Lock()
stats = {"processed": 0, "successful": 0, "failed": 0, "duplicates": 0}
stats_lock = threading.Lock()

# ==================== PROTOBUF DEFINITIONS (embedded) ====================
_sym_db = _symbol_database.Default()

GAMEDATA_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x08my.proto\"\xae\t\n\x08GameData\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x14\n\x0cgame_version\x18\x05 \x01(\x05\x12\x14\n\x0cversion_code\x18\x07 \x01(\t\x12\x0f\n\x07os_info\x18\x08 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\t \x01(\t\x12\x18\n\x10network_provider\x18\n \x01(\t\x12\x17\n\x0f\x63onnection_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\x05\x12\x15\n\rscreen_height\x18\r \x01(\x05\x12\x0b\n\x03\x64pi\x18\x0e \x01(\t\x12\x10\n\x08\x63pu_info\x18\x0f \x01(\t\x12\x11\n\ttotal_ram\x18\x10 \x01(\x05\x12\x10\n\x08gpu_name\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x0f\n\x07user_id\x18\x13 \x01(\t\x12\x12\n\nip_address\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x15\n\rplatform_type\x18\x17 \x01(\x05\x12\x1a\n\x12\x64\x65vice_form_factor\x18\x18 \x01(\t\x12\x14\n\x0c\x64\x65vice_model\x18\x19 \x01(\t\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x18\n\x10unknown_field_30\x18\x1e \x01(\x05\x12\"\n\x1asecondary_network_provider\x18) \x01(\t\x12!\n\x19secondary_connection_type\x18* \x01(\t\x12\x11\n\tunique_id\x18\x39 \x01(\t\x12\x10\n\x08\x66ield_60\x18< \x01(\x05\x12\x10\n\x08\x66ield_61\x18= \x01(\x05\x12\x10\n\x08\x66ield_62\x18> \x01(\x05\x12\x10\n\x08\x66ield_63\x18? \x01(\x05\x12\x10\n\x08\x66ield_64\x18@ \x01(\x05\x12\x10\n\x08\x66ield_65\x18\x41 \x01(\x05\x12\x10\n\x08\x66ield_66\x18\x42 \x01(\x05\x12\x10\n\x08\x66ield_67\x18\x43 \x01(\x05\x12\x10\n\x08\x66ield_70\x18\x46 \x01(\x05\x12\x10\n\x08\x66ield_73\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x10\n\x08\x66ield_76\x18L \x01(\x05\x12\x10\n\x08\x61pk_info\x18M \x01(\t\x12\x10\n\x08\x66ield_78\x18N \x01(\x05\x12\x10\n\x08\x66ield_79\x18O \x01(\x05\x12\x17\n\x0fos_architecture\x18Q \x01(\t\x12\x14\n\x0c\x62uild_number\x18S \x01(\t\x12\x10\n\x08\x66ield_85\x18U \x01(\x05\x12\x18\n\x10graphics_backend\x18V \x01(\t\x12\x19\n\x11max_texture_units\x18W \x01(\x05\x12\x15\n\rrendering_api\x18X \x01(\x05\x12\x18\n\x10\x65ncoded_field_89\x18Y \x01(\t\x12\x10\n\x08\x66ield_92\x18\\ \x01(\x05\x12\x13\n\x0bmarketplace\x18] \x01(\t\x12\x16\n\x0e\x65ncryption_key\x18^ \x01(\t\x12\x15\n\rtotal_storage\x18_ \x01(\x05\x12\x10\n\x08\x66ield_97\x18\x61 \x01(\x05\x12\x10\n\x08\x66ield_98\x18\x62 \x01(\x05\x12\x10\n\x08\x66ield_99\x18\x63 \x01(\t\x12\x11\n\tfield_100\x18\x64 \x01(\tb\x06proto3'
)
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(GAMEDATA_DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(GAMEDATA_DESCRIPTOR, 'my_pb2', _globals)
GameData = _sym_db.GetSymbol('GameData')

GARENA420_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13jwt_generator.proto\"\xd2\x02\n\nGarena_420\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05place\x18\x03 \x01(\t\x12\x10\n\x08location\x18\x04 \x01(\t\x12\x0e\n\x06status\x18\x05 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\n\n\x02id\x18\t \x01(\x05\x12\x0b\n\x03\x61pi\x18\n \x01(\t\x12\x0e\n\x06number\x18\x0c \x01(\x05\x12\x1e\n\tGarena420\x18\x0f \x01(\x0b\x32\x0b.Garena_420\x12\x0c\n\x04\x61rea\x18\x10 \x01(\t\x12\x11\n\tmain_area\x18\x12 \x01(\t\x12\x0c\n\x04\x63ity\x18\x13 \x01(\t\x12\x0c\n\x04name\x18\x14 \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0e\n\x06\x62inary\x18\x16 \x01(\x0c\x12\x13\n\x0b\x62inary_data\x18\x17 \x01(\x0c\x1a\"\n\x12\x44\x65\x63rypted_Payloads\x12\x0c\n\x04type\x18\x01 \x01(\x05b\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(GARENA420_DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(GARENA420_DESCRIPTOR, 'output_pb2', _globals)
Garena_420 = _sym_db.GetSymbol('Garena_420')

# ==================== CRYPTO ====================
def encrypt_data(data_bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

# ==================== HELPERS ====================
def decode_jwt(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return str(decoded.get("account_id")), decoded.get("nickname"), decoded.get("lock_region")
    except:
        return None, None, None

def get_openid_from_inspect(access_token):
    url = f"{INSPECT_URL}?token={access_token}"
    headers = {"User-Agent": "GarenaMSDK/4.0.30", "Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("open_id")
    except:
        pass
    return None

def login_with_uid_pass(uid, password):
    """Login to Garena using UID and password to get access token"""
    try:
        device_id = hashlib.md5(f"{uid}{time.time()}{random.random()}".encode()).hexdigest()
        
        login_data = {
            "username": uid,
            "password": password,
            "grant_type": "password",
            "client_id": "100067",
            "client_secret": "e23e884daa5bd67944b2c6c0f57b240c",
        }
        
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Device-Id": device_id
        }
        
        response = requests.post(
            "https://account.garena.com/api/v1/login",
            json=login_data,
            headers=headers,
            timeout=15,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("code") == 0 and data.get("data", {}).get("access_token"):
                return data["data"]["access_token"]
        
        alt_data = {
            "email": uid if '@' in uid else None,
            "username": uid if '@' not in uid else None,
            "password": password
        }
        
        alt_response = requests.post(
            "https://api.garena.com/auth/v1/login",
            json=alt_data,
            headers={"User-Agent": "Garena/4.0.30", "Content-Type": "application/json"},
            timeout=15,
            verify=False
        )
        
        if alt_response.status_code == 200:
            alt_json = alt_response.json()
            if alt_json.get("access_token"):
                return alt_json["access_token"]
        
        return None
    except Exception as e:
        return None

def major_login(access_token, open_id):
    platforms = [8, 3, 4, 6, 1, 2, 5, 7]
    
    for pt in platforms:
        try:
            game = GameData()
            game.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            game.game_name = "free fire"
            game.game_version = 1
            game.version_code = "2.124.1"
            game.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game.device_type = "Handheld"
            game.network_provider = "Verizon Wireless"
            game.connection_type = "WIFI"
            game.screen_width = 1280
            game.screen_height = 960
            game.dpi = "240"
            game.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game.total_ram = 5951
            game.gpu_name = "Adreno (TM) 640"
            game.gpu_version = "OpenGL ES 3.0"
            game.user_id = f"Google|{hashlib.md5(open_id.encode()).hexdigest()}"
            game.ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
            game.language = "en"
            game.open_id = open_id
            game.access_token = access_token
            game.platform_type = pt
            game.field_99 = str(pt)
            game.field_100 = str(pt)

            ser = game.SerializeToString()
            enc = encrypt_data(ser)
            edata = bytes.fromhex(binascii.hexlify(enc).decode('utf-8'))
            resp = requests.post(MAJOR_LOGIN_URL, data=edata, headers=LOGIN_HEADERS, verify=False, timeout=10)
            
            if resp.status_code == 200:
                msg = Garena_420()
                msg.ParseFromString(resp.content)
                if msg.token:
                    return msg.token
        except:
            continue
    return None

def process_access_token(access_token, timestamp=None):
    """Process a single access token and return result dict with timestamp"""
    if timestamp is None:
        timestamp = time.time()
    
    # Check cache first
    with token_cache_lock:
        if access_token in token_cache:
            cached_result = token_cache[access_token]
            # If cached result is newer, return it
            if cached_result.get('timestamp', 0) >= timestamp:
                with stats_lock:
                    stats['duplicates'] += 1
                return cached_result.get('result')
    
    result = {
        "access_token": access_token,
        "success": False,
        "jwt": None,
        "uid": None,
        "region": None,
        "error": None,
        "timestamp": timestamp
    }
    
    open_id = get_openid_from_inspect(access_token)
    if not open_id:
        result["error"] = "Invalid access token or could not fetch open_id"
        with token_cache_lock:
            token_cache[access_token] = {'result': result, 'timestamp': timestamp}
        return result
    
    jwt_token = major_login(access_token, open_id)
    if not jwt_token:
        result["error"] = "MajorLogin failed. Token may be expired or invalid"
        with token_cache_lock:
            token_cache[access_token] = {'result': result, 'timestamp': timestamp}
        return result
    
    uid, name, region = decode_jwt(jwt_token)
    if uid:
        result["success"] = True
        result["jwt"] = jwt_token
        result["uid"] = uid
        result["region"] = region
        result["nickname"] = name
    else:
        result["error"] = "Failed to decode JWT"
    
    # Cache the result with timestamp
    with token_cache_lock:
        if access_token not in token_cache or token_cache[access_token]['timestamp'] < timestamp:
            token_cache[access_token] = {'result': result, 'timestamp': timestamp}
    
    return result

def process_uid_pass(uid, password, timestamp=None):
    """Process UID:PASS combination to get JWT"""
    if timestamp is None:
        timestamp = time.time()
    
    result = {
        "uid": uid,
        "password": password,
        "success": False,
        "jwt": None,
        "region": None,
        "access_token": None,
        "error": None,
        "timestamp": timestamp
    }
    
    access_token = login_with_uid_pass(uid, password)
    if not access_token:
        result["error"] = "Failed to login with UID:PASS - invalid credentials"
        return result
    
    result["access_token"] = access_token
    
    jwt_result = process_access_token(access_token, timestamp)
    
    if jwt_result.get("success"):
        result["success"] = True
        result["jwt"] = jwt_result["jwt"]
        result["region"] = jwt_result["region"]
        result["uid"] = jwt_result["uid"]
    else:
        result["error"] = jwt_result.get("error", "Unknown error")
    
    return result

def load_tokens_from_json(filepath):
    """Load tokens from JSON file with auto-repair for common issues"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Fix common JSON issues
    content = re.sub(r',\s*\]', ']', content)
    content = re.sub(r',\s*\}', '}', content)
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        import ast
        try:
            data = ast.literal_eval(content)
        except:
            raise json.JSONDecodeError(f"Invalid JSON: {e}", content, e.pos)
    
    tokens = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                token = item.get('token') or item.get('access_token') or item.get('ACCESS TOKEN')
                if token:
                    tokens.append(token)
            elif isinstance(item, str):
                tokens.append(item)
    elif isinstance(data, dict):
        token = data.get('token') or data.get('access_token') or data.get('ACCESS TOKEN')
        if token:
            tokens.append(token)
    
    return tokens

def load_credentials_from_file(filepath):
    """Load UID:PASS pairs from txt file (one per line)"""
    credentials = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line:
                uid, password = line.split(':', 1)
                credentials.append({'uid': uid.strip(), 'password': password.strip()})
    return credentials

def save_results_to_json(results, output_file="jwttoken.json"):
    """Save results to JSON file in the SAME directory as the script"""
    # Deduplicate results - keep only the latest for each UID or token
    latest_results = {}
    
    for r in results:
        if r.get('success') and r.get('jwt'):
            key = r.get('uid') or r.get('access_token')
            if key:
                if key not in latest_results or latest_results[key].get('timestamp', 0) < r.get('timestamp', 0):
                    latest_results[key] = r
    
    # Convert to output format
    output = []
    for r in latest_results.values():
        if r.get('success') and r.get('jwt'):
            region = r.get('region', 'ind').lower()
            api_url = f"https://client.{region}.freefiremobile.com"
            
            output.append({
                "uid": r.get('uid'),
                "token": r.get('jwt'),
                "region": r.get('region'),
                "api": api_url,
                "generated_at": datetime.now().isoformat()
            })
    
    # Save to script directory
    script_output_path = os.path.join(SCRIPT_DIR, output_file)
    
    with open(script_output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"💾 Saved {len(output)} unique JWTs to: {script_output_path}")
    
    # Also save raw access tokens if any
    access_tokens = list(set([r.get('access_token') for r in latest_results.values() if r.get('access_token')]))
    
    if access_tokens:
        access_token_path = os.path.join(SCRIPT_DIR, "access_tokens.json")
        with open(access_token_path, 'w') as f:
            json.dump(access_tokens, f, indent=2)
        print(f"💾 Saved {len(access_tokens)} unique access tokens to: {access_token_path}")
    
    return script_output_path, len(output)

def bulk_process_threaded(items, process_func, max_workers=5, delay=0):
    """Process items in parallel with thread pooling and smart deduplication"""
    results = []
    completed = 0
    total = len(items)
    
    # Create a queue for items
    item_queue = Queue()
    for item in items:
        item_queue.put(item)
    
    def worker():
        nonlocal completed
        while True:
            try:
                item = item_queue.get(timeout=1)
            except:
                break
            
            # Add timestamp to track freshness
            timestamp = time.time()
            
            if isinstance(item, dict) and 'access_token' in item:
                result = process_func(item['access_token'], timestamp)
            elif isinstance(item, dict) and 'uid' in item:
                result = process_func(item['uid'], item['password'], timestamp)
            elif isinstance(item, str):
                result = process_func(item, timestamp)
            else:
                result = {"success": False, "error": "Invalid item type"}
            
            with results_lock:
                results.append(result)
                completed += 1
                
                # Update stats
                with stats_lock:
                    if result.get('success'):
                        stats['successful'] += 1
                    else:
                        stats['failed'] += 1
                    stats['processed'] += 1
                
                # Progress report
                status = "✅" if result.get('success') else "❌"
                identifier = result.get('uid') or result.get('access_token', str(item))[:20]
                print(f"[{completed}/{total}] {status} {identifier} - {result.get('error', 'Success')[:50]}")
            
            if delay > 0:
                time.sleep(delay)
            
            item_queue.task_done()
    
    # Create thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker) for _ in range(max_workers)]
        for future in as_completed(futures):
            pass
    
    return results

def smart_deduplicate_tokens(tokens):
    """Remove duplicate tokens while preserving order of first occurrence"""
    seen = set()
    unique_tokens = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            unique_tokens.append(token)
        else:
            with stats_lock:
                stats['duplicates'] += 1
    return unique_tokens

def create_sample_files():
    """Create sample input files in the script directory"""
    # Sample tokens.json
    tokens_path = os.path.join(SCRIPT_DIR, "tokens.json")
    if not os.path.exists(tokens_path):
        sample_tokens = [
            "YOUR_ACCESS_TOKEN_1_HERE",
            "YOUR_ACCESS_TOKEN_2_HERE",
            "YOUR_ACCESS_TOKEN_3_HERE"
        ]
        with open(tokens_path, 'w') as f:
            json.dump(sample_tokens, f, indent=2)
        print(f"📝 Created sample tokens.json at: {tokens_path}")
    
    # Sample credentials.txt
    creds_path = os.path.join(SCRIPT_DIR, "credentials.txt")
    if not os.path.exists(creds_path):
        with open(creds_path, 'w') as f:
            f.write("UID1:PASSWORD1\n")
            f.write("UID2:PASSWORD2\n")
            f.write("email@example.com:password123\n")
        print(f"📝 Created sample credentials.txt at: {creds_path}")

def interactive_mode():
    """Interactive mode for single token processing"""
    print("\n🔐 ACCESS TOKEN → JWT GENERATOR (INTERACTIVE MODE)")
    print("=" * 50)
    
    token = input("\nEnter Access Token: ").strip()
    if not token:
        print("❌ No token provided.")
        return
    
    print("\n🔄 Processing...")
    result = process_access_token(token)
    
    if result.get('success'):
        print("\n✅ JWT GENERATED SUCCESSFULLY!")
        print("=" * 60)
        print(f"🔑 JWT TOKEN:\n{result['jwt']}\n")
        print(f"🆔 UID   : {result['uid']}")
        print(f"👤 Name  : {result.get('nickname', 'N/A')}")
        print(f"🌍 Region: {result['region']}")
        print("=" * 60)
        
        # Save single result
        save_results_to_json([result], "jwttoken.json")
        
        # Ask to save raw token
        save_raw = input("\nSave raw JWT to file? (y/n): ").strip().lower()
        if save_raw == 'y':
            raw_path = os.path.join(SCRIPT_DIR, "jwt_token.txt")
            with open(raw_path, 'w') as f:
                f.write(result['jwt'])
            print(f"💾 Saved to: {raw_path}")
    else:
        print(f"\n❌ Failed: {result['error']}")

def main():
    print(f"\n📁 Script directory: {SCRIPT_DIR}")
    print("=" * 60)
    print("🔐 ACCESS TOKEN → JWT GENERATOR (MULTI-THREADED)")
    print("=" * 60)
    print("Options:")
    print("  1. Single Access Token (Interactive)")
    print("  2. Bulk from JSON file (access tokens) - Multi-threaded")
    print("  3. Bulk from TXT file (UID:PASS format) - Multi-threaded")
    print("  4. Create sample input files")
    print("=" * 60)
    
    choice = input("\nSelect option (1/2/3/4): ").strip()
    
    if choice == "1":
        interactive_mode()
    
    elif choice == "2":
        filepath = input("Enter JSON file path [tokens.json]: ").strip()
        if not filepath:
            filepath = os.path.join(SCRIPT_DIR, "tokens.json")
        
        if not os.path.exists(filepath):
            print(f"❌ File not found: {filepath}")
            create_sample = input("Create sample tokens.json? (y/n): ").strip().lower()
            if create_sample == 'y':
                create_sample_files()
            return
        
        try:
            # Load and deduplicate tokens
            tokens = load_tokens_from_json(filepath)
            if not tokens:
                print("❌ No tokens found in JSON file")
                return
            
            original_count = len(tokens)
            tokens = smart_deduplicate_tokens(tokens)
            
            print(f"✅ Loaded {original_count} tokens from: {filepath}")
            print(f"📊 After deduplication: {len(tokens)} unique tokens")
            if original_count - len(tokens) > 0:
                print(f"🗑️ Removed {original_count - len(tokens)} duplicates")
            
            # Thread settings
            max_workers = input("Number of threads [5]: ").strip()
            max_workers = int(max_workers) if max_workers else 5
            
            delay = input("Delay between requests (seconds) [0.5]: ").strip()
            delay = float(delay) if delay else 0.5
            
            print(f"\n🚀 Starting with {max_workers} threads...")
            print("=" * 60)
            
            start_time = time.time()
            
            # Process with threading
            results = bulk_process_threaded(tokens, process_access_token, max_workers, delay)
            
            elapsed = time.time() - start_time
            
            # Save results
            output_file, count = save_results_to_json(results)
            
            # Summary
            print("\n" + "=" * 60)
            print("📊 FINAL SUMMARY:")
            print(f"   Total tokens processed: {len(results)}")
            print(f"   ✅ Successful: {stats['successful']}")
            print(f"   ❌ Failed: {stats['failed']}")
            print(f"   🔄 Duplicates skipped: {stats['duplicates']}")
            print(f"   ⏱️ Time taken: {elapsed:.2f} seconds")
            print(f"   🚀 Average speed: {len(results)/elapsed:.2f} tokens/sec")
            print("=" * 60)
            
            # Show failed tokens
            failed_results = [r for r in results if not r.get('success')]
            if failed_results:
                print("\n❌ Failed tokens (first 10):")
                for r in failed_results[:10]:
                    print(f"  - {r.get('access_token', 'Unknown')[:30]}... ({r.get('error')})")
                if len(failed_results) > 10:
                    print(f"  ... and {len(failed_results) - 10} more")
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON file format: {e}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    elif choice == "3":
        filepath = input("Enter TXT file path [credentials.txt]: ").strip()
        if not filepath:
            filepath = os.path.join(SCRIPT_DIR, "credentials.txt")
        
        if not os.path.exists(filepath):
            print(f"❌ File not found: {filepath}")
            create_sample = input("Create sample credentials.txt? (y/n): ").strip().lower()
            if create_sample == 'y':
                create_sample_files()
            return
        
        credentials = load_credentials_from_file(filepath)
        if not credentials:
            print("❌ No credentials found in file")
            return
        
        print(f"✅ Loaded {len(credentials)} UID:PASS pairs from: {filepath}")
        
        # Thread settings
        max_workers = input("Number of threads [3]: ").strip()
        max_workers = int(max_workers) if max_workers else 3
        
        delay = input("Delay between requests (seconds) [1]: ").strip()
        delay = float(delay) if delay else 1
        
        print(f"\n🚀 Starting with {max_workers} threads...")
        print("=" * 60)
        
        start_time = time.time()
        
        # Process with threading
        results = bulk_process_threaded(credentials, process_uid_pass, max_workers, delay)
        
        elapsed = time.time() - start_time
        
        # Save only successful ones
        successful_results = [r for r in results if r.get('success')]
        if successful_results:
            output_file, count = save_results_to_json(successful_results)
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 FINAL SUMMARY:")
        print(f"   Total credentials processed: {len(results)}")
        print(f"   ✅ Successful: {stats['successful']}")
        print(f"   ❌ Failed: {stats['failed']}")
        print(f"   🔄 Duplicates skipped: {stats['duplicates']}")
        print(f"   ⏱️ Time taken: {elapsed:.2f} seconds")
        print("=" * 60)
        
        # Show failed credentials
        failed_results = [r for r in results if not r.get('success')]
        if failed_results:
            print("\n❌ Failed credentials (first 10):")
            for r in failed_results[:10]:
                print(f"  - {r.get('uid')}:{r.get('password', '')[:5]}*** ({r.get('error')})")
            if len(failed_results) > 10:
                print(f"  ... and {len(failed_results) - 10} more")
    
    elif choice == "4":
        create_sample_files()
        print(f"\n✅ Sample files created in: {SCRIPT_DIR}")
        print("  - tokens.json (for access tokens)")
        print("  - credentials.txt (for UID:PASS pairs)")
        print("\nEdit these files with your data, then run option 2 or 3.")
    
    else:
        print("❌ Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")