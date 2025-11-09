# -*- coding: utf-8 -*-

# CHANGELOG (FlareProx Edition v15.0 - Performance & Optimization Update):
# 1. CONCURRENCY: `process_single_request` now uses `asyncio.gather` to analyze all discovered parameters concurrently, massively speeding up scans on targets with multiple reflected params.
# 2. STATUS LOGGING: `run_batched_discovery` now logs the HTTP status code for each batch, making it easy to spot rate-limiting or server errors.
# 3. POST OPTIMIZATION: `run_post_character_probe` now performs a "preflight" check. It sends one simple POST request per content-type to verify reflectivity before launching the full, expensive character-by-character scan, avoiding wasted requests.
# 4. REFACTORED: Logic for analyzing a single parameter was moved into a dedicated `analyze_single_param` helper function for clarity and to support concurrency.

import asyncio
import logging
import random
import string
import sys
import re
import base64
import binascii
import math
import time
import html
import cgi
import io
from bs4 import BeautifulSoup
from contextlib import asynccontextmanager
from typing import Dict, List, Set, Optional, DefaultDict
from urllib.parse import urlparse, urlencode, quote, parse_qs, parse_qsl,unquote
from collections import defaultdict

import httpx
import uvicorn
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

# --- Configuration & Global Variables ---
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1436400670117724210/I-f7DmhaBWrhvhw47knIYgl7YDKJ2khr7ZyScCgxRd9X38t5tqHet9CuNrH6gfkR53Cy"
PARAMS_FILE = "params.txt"
FLAREPROX_WORKERS = [
    "https://flareprox-1762412955-ouctlr.amirpkr69.workers.dev", "https://flareprox-1762412960-zszgku.amirpkr69.workers.dev",
    "https://flareprox-1762412963-xevmlt.amirpkr69.workers.dev", "https://flareprox-1762412965-rhvkyu.amirpkr69.workers.dev",
    "https://flareprox-1762412972-emyqoz.amirpkr69.workers.dev", "https://flareprox-1762529342-rlgbvx.amirpkr69.workers.dev",
    "https://flareprox-1762529346-grnvde.amirpkr69.workers.dev", "https://flareprox-1762529349-klzgv.amirpkr69.workers.dev",
    "https://flareprox-1762529352-caazhh.amirpkr69.workers.dev", "https://flareprox-1762529355-bvptcj.amirpkr69.workers.dev",
    "https://flareprox-1762529361-kbhiud.amirpkr69.workers.dev", "https://flareprox-1762529365-qebmer.amirpkr69.workers.dev",
    "https://flareprox-1762529367-lwpynz.amirpkr69.workers.dev", "https://flareprox-1762529371-zrqrox.amirpkr69.workers.dev",
    "https://flareprox-1762529376-nlyvnd.amirpkr69.workers.dev", "https://flareprox-1762529379-habqnw.amirpkr69.workers.dev",
    "https://flareprox-1762529383-tbcbit.amirpkr69.workers.dev", "https://flareprox-1762529386-kmdbnk.amirpkr69.workers.dev",
    "https://flareprox-1762529389-jmpsov.amirpkr69.workers.dev", "https://flareprox-1762529392-zblhcs.amirpkr69.workers.dev",
    "https://flareprox-1762529395-rqnbbg.amirpkr69.workers.dev", "https://flareprox-1762529398-viuxhe.amirpkr69.workers.dev",
    "https://flareprox-1762529403-bwdbtv.amirpkr69.workers.dev", "https://flareprox-1762529410-skfjcv.amirpkr69.workers.dev",
    "https://flareprox-1762529415-usjarx.amirpkr69.workers.dev", "https://flareprox-1762529420-vxklkv.amirpkr69.workers.dev",
    "https://flareprox-1762529424-udhqbg.amirpkr69.workers.dev", "https://flareprox-1762529428-mocuok.amirpkr69.workers.dev",
    "https://flareprox-1762529432-kizbnq.amirpkr69.workers.dev", "https://flareprox-1762529434-kfofxv.amirpkr69.workers.dev"
]

# Add these new constants near the top of your processor_server.py file
DELAY_BETWEEN_BATCHES = 2.0       # Increase to 1 second for safety
DELAY_BETWEEN_CONFIRMATIONS = 1.5 # Increase to 0.5 seconds for safety
DELAY_BETWEEN_PROBES = 0.3


HEADER_BLACKLIST = {'host', 'content-length', 'connection'}
DISCOVERY_BATCH_SIZE = 40
MAX_RETRIES = 30
PROBE_CHARS = ['<', '>', '"', "'"]

ENCODING_MAP = {
    '<': {'raw': '<', 'url': '%3C', 'double_url': '%253C', 'html_entity_named': '&lt;', 'html_entity_decimal': '&#60;', 'unicode_escape': '\u003c'},
    '>': {'raw': '>', 'url': '%3E', 'double_url': '%253E', 'html_entity_named': '&gt;', 'html_entity_decimal': '&#62;', 'unicode_escape': '\u003e'},
    '"': {'raw': '"', 'url': '%22', 'double_url': '%2522', 'html_entity_named': '&quot;', 'html_entity_decimal': '&#34;', 'unicode_escape': '\u0022'},
    "'": {'raw': "'", 'url': '%27', 'double_url': '%2527', 'html_entity_named': '&apos;', 'html_entity_decimal': '&#39;', 'unicode_escape': '\u0027'},
}

PARAMS_TO_TEST: List[str] = []
processed_urls_lock = asyncio.Lock()
PROCESSED_URLS: Set[str] = set()

C_RED, C_GREEN, C_YELLOW, C_BLUE, C_MAGENTA, C_CYAN, C_END = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[0m"
log_formatter = logging.Formatter(f"{C_CYAN}%(asctime)s{C_END} - %(message)s", datefmt='%H:%M:%S')
console_logger = logging.getLogger("console")
console_logger.setLevel(logging.INFO)
if not console_logger.handlers:
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    console_logger.addHandler(stream_handler)

class RequestItem(BaseModel): url: str; method: str; headers: List[str]; body: str
class RequestBatch(BaseModel): requests: List[RequestItem]

def generate_random_string(length=8): return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
def get_batches(items: List, size: int): 
    for i in range(0, len(items), size): yield items[i:i + size]
def append_query(base_url, query_str): return f"{base_url}{'&' if '?' in base_url else '?'}{query_str}"
def get_flareprox_worker() -> Optional[str]: return random.choice(FLAREPROX_WORKERS) if FLAREPROX_WORKERS else None
def headers_list_to_dict(h_list: List[str]) -> Dict[str, str]:
    headers = {};
    for h in h_list[1:]:
        if ':' in h: key, value = h.split(':', 1); headers[key.strip()] = value.strip()
    return headers

async def send_summary_discord_notification(base_url: str, param: str, results: DefaultDict[str, List[str]]):
    if not DISCORD_WEBHOOK_URL or "YOUR_DISCORD_WEBHOOK_URL" in DISCORD_WEBHOOK_URL: return

    description = ""
    sorted_chars = sorted(results.keys(), key=lambda c: PROBE_CHARS.index(c) if c in PROBE_CHARS else 99)
    for char in sorted_chars:
        escaped_char = html.escape(char)
        methods_str = ", ".join(f"`{method}`" for method in sorted(results[char]))
        description += f"**`{escaped_char}`** → {methods_str}\n"

    if not description: return

    embed = {
        "title": "XSS Vulnerability Summary", "color": 16711680,
        "fields": [
            {"name": "URL", "value": f"\n```{base_url}```", "inline": False},
            {"name": "Parameter", "value": f"`{param}`", "inline": False},
            {"name": "Bypassed Characters & Methods", "value": description, "inline": False},
        ],
        "footer": {"text": "Hunter's XSS Server"}
    }
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]})
    except Exception as e:
        console_logger.error(f"{C_RED}[!] Failed to send summary Discord notification: {e}{C_END}")

def load_parameters_from_file():
    global PARAMS_TO_TEST
    try:
        with open(PARAMS_FILE, mode='r') as f: PARAMS_TO_TEST = [line.strip() for line in f.readlines() if line.strip()]
        console_logger.info(f"{C_GREEN}[*] Loaded {len(PARAMS_TO_TEST)} parameters from '{PARAMS_FILE}'.{C_END}")
    except FileNotFoundError:
        console_logger.warning(f"{C_YELLOW}[!] Parameter file '{PARAMS_FILE}' not found. Discovery will be based on request params only.{C_END}"); PARAMS_TO_TEST = []

# In processor_server.py
# REPLACE your entire make_request_with_retries function with this FIXED version

def generate_natural_marker(prefix: str) -> str:
    """Generate a more natural-looking marker that might bypass WAF"""
    timestamp = str(int(time.time() * 1000))[-6:]  # Last 6 digits of timestamp
    return f"{prefix}{timestamp}"

# در تابع run_post_character_probe_with_body:
marker_start = generate_natural_marker("val")  # مثلاً: val123456
marker_end = generate_natural_marker("end")    # مثلاً: end789012


# ========================================
# STEP 1: اضافه کردن Global State Tracking
# ========================================

# ========================================
# Global Tracking Variables
# ========================================
FAILED_WORKERS_BY_DOMAIN: DefaultDict[str, Set[str]] = defaultdict(set)
GLOBAL_WORKER_HEALTH: DefaultDict[str, int] = defaultdict(lambda: 10)  # Default score: 10


def get_best_worker_for_domain(domain: str, exclude_workers: Optional[Set[str]] = None) -> Optional[str]:
    """
    انتخاب بهترین worker برای یک domain خاص
    - Worker هایی که برای این domain fail شدن رو exclude میکنه
    - Worker هایی که health score بالاتری دارن رو ترجیح میده
    """
    if exclude_workers is None:
        exclude_workers = set()
    
    # Worker های قابل استفاده
    failed_for_domain = FAILED_WORKERS_BY_DOMAIN.get(domain, set())
    available_workers = [
        w for w in FLAREPROX_WORKERS 
        if w not in exclude_workers and w not in failed_for_domain
    ]
    
    if not available_workers:
        # اگه همه fail شدن، از همه استفاده کن (شاید الان درست شده باشن)
        console_logger.warning(f"{C_YELLOW}[!] All workers marked as failed for {domain}. Trying all again.{C_END}")
        available_workers = [w for w in FLAREPROX_WORKERS if w not in exclude_workers]
    
    if not available_workers:
        return None
    
    # Sort کن بر اساس health score (بهترین worker رو برگردون)
    sorted_workers = sorted(available_workers, key=lambda w: GLOBAL_WORKER_HEALTH.get(w, 0), reverse=True)
    return sorted_workers[0]


def mark_worker_failed(worker: str, domain: str):
    """Worker رو برای این domain به عنوان failed علامت بزن"""
    FAILED_WORKERS_BY_DOMAIN[domain].add(worker)
    GLOBAL_WORKER_HEALTH[worker] -= 10  # کاهش score
    
    # محدود کردن به حداقل -20
    if GLOBAL_WORKER_HEALTH[worker] < -20:
        GLOBAL_WORKER_HEALTH[worker] = -20
    
    worker_short = worker.split('/')[-1][:20]
    console_logger.debug(
        f"{C_RED}[Worker Health] {worker_short}... marked as failed for {domain} "
        f"(Score: {GLOBAL_WORKER_HEALTH[worker]}){C_END}"
    )


def mark_worker_success(worker: str):
    """Worker موفق بود، score رو افزایش بده"""
    GLOBAL_WORKER_HEALTH[worker] += 1
    if GLOBAL_WORKER_HEALTH[worker] > 50:  # Cap at 50
        GLOBAL_WORKER_HEALTH[worker] = 50


# ========================================
# ENHANCED make_request_with_retries با Smart Worker Rotation
# ========================================

async def make_request_with_retries(
    target_url: str, 
    headers: Dict, 
    log_prefix: str, 
    method: str = "GET", 
    data=None, 
    files=None,
    max_retries: Optional[int] = None
) -> Optional[httpx.Response]:
    """
    ✅ ENHANCED VERSION با Smart Worker Rotation
    - هر retry از worker متفاوت استفاده میکنه
    - Worker های fail شده رو track میکنه
    """
    if max_retries is None:
        max_retries = MAX_RETRIES
    
    parsed = urlparse(target_url)
    domain = parsed.netloc
    
    used_workers_this_request: Set[str] = set()
    
    for attempt in range(max_retries):
        # ✅ انتخاب worker بر اساس domain و worker های قبلی
        worker = get_best_worker_for_domain(domain, exclude_workers=used_workers_this_request)
        
        if not worker:
            console_logger.error(f"{C_RED}{log_prefix} No available workers left.{C_END}")
            return None
        
        used_workers_this_request.add(worker)
        worker_name = worker.split('/')[-1][:20]
        
        final_url = f"{worker}?url={quote(target_url)}"
        req_headers = headers.copy()
        
        # Remove Content-Type for multipart (httpx handles it)
        if files:
            req_headers.pop('Content-Type', None)
            req_headers.pop('content-type', None)
        elif data and not files and 'content-type' not in (k.lower() for k in req_headers):
            req_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                req = client.build_request(method.upper(), final_url, headers=req_headers, data=data, files=files)
                response = await client.send(req)
                
                # ✅ اگه 403 یا 429 بود، این worker رو برای این domain failed علامت بزن
                if response.status_code in [403, 429]:
                    mark_worker_failed(worker, domain)
                    
                    if attempt < max_retries - 1:
                        console_logger.warning(
                            f"{C_YELLOW}{log_prefix} Worker '{worker_name}...' blocked (Status: {response.status_code}). "
                            f"Retrying with different worker ({attempt+1}/{max_retries})...{C_END}"
                        )
                        await asyncio.sleep(1.0 + (attempt * 0.5))  # Exponential backoff
                        continue
                    else:
                        console_logger.error(
                            f"{C_RED}{log_prefix} All retries exhausted (Status: {response.status_code}). Giving up.{C_END}"
                        )
                        return None
                
                # ✅ Status code های دیگه
                response.raise_for_status()
                
                # ✅ موفق بود! score رو افزایش بده
                mark_worker_success(worker)
                return response
        
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            
            # اگه 403/429 بود، worker رو failed علامت بزن
            if status_code in [403, 429]:
                mark_worker_failed(worker, domain)
            
            if attempt < max_retries - 1:
                console_logger.debug(
                    f"{C_YELLOW}{log_prefix} Attempt {attempt+1}/{max_retries} with '{worker_name}...' "
                    f"failed (Status: {status_code}). Retrying...{C_END}"
                )
                await asyncio.sleep(1.0 * (attempt + 1))
            else:
                console_logger.error(
                    f"{C_RED}{log_prefix} Final attempt failed for {target_url}: "
                    f"HTTPStatusError (Status: {status_code}). Giving up.{C_END}"
                )
        
        except httpx.RequestError as e:
            error_type = type(e).__name__
            mark_worker_failed(worker, domain)  # Network error = worker مشکل داره
            
            if attempt < max_retries - 1:
                console_logger.debug(
                    f"{C_YELLOW}{log_prefix} Network error with '{worker_name}...' ({error_type}). Retrying...{C_END}"
                )
                await asyncio.sleep(0.5)
            else:
                console_logger.error(
                    f"{C_RED}{log_prefix} Final attempt failed: {error_type}. Giving up.{C_END}"
                )
    
    return None


# ========================================
# Batch-Level Retry Wrapper
# ========================================

async def run_batched_discovery_with_retry(
    full_url: str,
    method: str,
    headers: Dict,
    original_body_bytes: bytes,
    baseline_count: int,
    params_to_test: List[str],
    max_batch_retries: int = 2
) -> List[str]:  # ✅ FIXED: Return List instead of Set
    """
    ✅ Wrapper around run_batched_discovery که batch های fail شده رو retry میکنه
    """
    found_params: List[str] = []  # ✅ Use List to match run_batched_discovery return type
    
    for batch_attempt in range(max_batch_retries):
        console_logger.info(
            f"{C_CYAN}[Phase 2] Batch Discovery Attempt {batch_attempt+1}/{max_batch_retries}...{C_END}"
        )
        
        # اجرای discovery اصلی
        batch_results = await run_batched_discovery(
            full_url=full_url,
            method=method,
            headers=headers,
            original_body_bytes=original_body_bytes,
            baseline_count=baseline_count,
            params_to_test=params_to_test
        )
        
        # ✅ Merge results (avoid duplicates)
        for param in batch_results:
            if param not in found_params:
                found_params.append(param)
        
        # اگه چیزی پیدا شد یا آخرین attempt بود، متوقف شو
        if batch_results or batch_attempt == max_batch_retries - 1:
            break
        
        # اگه هیچی پیدا نشد، با تاخیر بیشتر دوباره امتحان کن
        console_logger.warning(
            f"{C_YELLOW}[Phase 2] No params found in attempt {batch_attempt+1}. "
            f"Retrying with different workers...{C_END}"
        )
        await asyncio.sleep(2.0)
    
    return found_params







# Constants (for context, assuming they are defined elsewhere)
C_CYAN = "\033[36m"
C_END = "\033[0m"
C_BLUE = "\033[94m"
C_YELLOW = "\033[93m"

import json

def is_reflection_in_unsafe_context(text: str, marker_start: str, marker_end: str, char: str) -> bool:
    """
    ✅ FIXED: Handles both HTML and JSON responses correctly.
    If response is JSON, we skip BeautifulSoup and search directly.
    """
    try:
        full_marker_string = f"{marker_start}{char}{marker_end}"
        unescaped_text = html.unescape(text)

        console_logger.debug(f"  [DEBUG] Looking for marker: '{full_marker_string}' in response...")

        if full_marker_string not in unescaped_text:
            console_logger.debug(f"  [DEBUG] ❌ Marker NOT found in unescaped text")
            return False

        console_logger.debug(f"  [DEBUG] ✅ Marker FOUND in unescaped text!")

        # ✅✅✅ NEW: Check if response is JSON ✅✅✅
        try:
            json.loads(text)  # Try to parse as JSON
            console_logger.debug(f"  [DEBUG] ✅ Response is valid JSON - marker found in JSON context!")
            return True  # If it's JSON and marker exists, it's reflected
        except (json.JSONDecodeError, ValueError):
            # Not JSON, continue with HTML parsing
            console_logger.debug(f"  [DEBUG] Response is NOT JSON, using HTML parsing...")
            pass

        # Original BeautifulSoup logic for HTML responses
        soup = BeautifulSoup(text, "html.parser")

        if soup.find(string=lambda s: full_marker_string in s):
            console_logger.debug(f"  [DEBUG] ✅ Marker found in HTML text nodes (unsafe context)!")
            return True

        console_logger.debug(f"  [DEBUG] ⚠️ Marker found but NOT in text nodes (might be in attributes)")
        return False

    except Exception as e:
        console_logger.debug(f"  [DEBUG] ⚠️ Exception in detection: {e}")
        # Fallback: simple string check
        return full_marker_string in html.unescape(text)


    except Exception as e:
        # Fallback mechanism: If BeautifulSoup fails (e.g., on JSON or malformed HTML),
        # rely on the fact that the raw string was present. This correctly handles JSON responses.
        console_logger.debug(f"  [DEBUG] ⚠️ Exception during HTML parsing: {e}. Falling back to raw string check result.")
        return full_marker_string in html.unescape(text)


async def establish_reflection_baseline(
    full_url: str,
    method: str,
    headers: Dict,
    original_body_bytes: bytes
) -> int:
    """
    Establishes a reflection baseline by sending multiple random parameters and finding the most common reflection count.
    This helps filter out "background noise" where frameworks might reflect all parameters a certain number of times.
    """
    console_logger.info(f"  {C_CYAN}[Phase 1] Establishing reflection baseline...{C_END}")

    num_probes = 5
    probe_params = {generate_random_string(8): generate_random_string(12) for _ in range(num_probes)}

    parsed_url = urlparse(full_url)
    base_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), "").lower()

    request_url = base_path
    request_data = None
    test_headers = headers.copy()
    test_headers.pop('Content-Length', None)
    test_headers.pop('content-length', None)

    # Build the request with all probe parameters
    if method.upper() == "GET":
        existing_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for key, value in probe_params.items():
            existing_params[key] = [value]
        request_url = f"{base_path}?{urlencode(existing_params, doseq=True)}"

    elif method.upper() == "POST":
        existing_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        if existing_query_params:
            request_url = f"{base_path}?{urlencode(existing_query_params, doseq=True)}"

        if 'application/x-www-form-urlencoded' in content_type:
            try:
                body_dict = dict(parse_qsl(original_body_bytes.decode('utf-8', errors='ignore')))
            except Exception:
                body_dict = {}

            for key, value in probe_params.items():
                body_dict[key] = value
            request_data = urlencode(body_dict).encode('utf-8')
        else: # Default to query params for other POST types if body is not urlencoded
            existing_params = parse_qs(parsed_url.query, keep_blank_values=True)
            for key, value in probe_params.items():
                existing_params[key] = [value]
            request_url = f"{base_path}?{urlencode(existing_params, doseq=True)}"


    # Make the request
    response = await make_request_with_retries(
        target_url=request_url,
        headers=test_headers,
        log_prefix="[Phase 1 Baseline]",
        method=method,
        data=request_data
    )

    if not response:
        console_logger.warning(f"  {C_YELLOW}[Phase 1] Failed to establish baseline. Assuming 0.{C_END}")
        return 0

    # Calculate the baseline from the response
    from collections import Counter
    response_text = html.unescape(response.text)
    counts = [response_text.count(marker) for marker in probe_params.values()]

    if not counts:
        return 0

    # Find the most common count
    count_freq = Counter(counts)
    most_common_count = count_freq.most_common(1)[0][0]

    console_logger.info(f"  {C_GREEN}[Phase 1] Reflection counts: {counts}. Most common is {most_common_count}. Baseline set to: {most_common_count}{C_END}")
    return most_common_count


# REPLACE your entire run_batched_discovery function with this new version


async def run_batched_discovery(full_url: str, method: str, headers: Dict, original_body_bytes: bytes, baseline_count: int, params_to_test: List[str]) -> Set[str]:
    """
    ✅ FINAL FIX: Preserves complex nested parameter structures like urls[0][longUrl]
    by treating the body as a raw string and appending test params carefully.
    """
    parsed_original_url = urlparse(full_url)
    base_path = f"{parsed_original_url.scheme}://{parsed_original_url.netloc}{parsed_original_url.path}"
    original_query_params = parse_qs(parsed_original_url.query, keep_blank_values=True)
    
    console_logger.info(f"  {C_CYAN}[Phase 2] Running batched discovery on {len(params_to_test)} params...{C_END}")
    found_params = set()
    param_batches = list(get_batches(params_to_test, DISCOVERY_BATCH_SIZE))
    total_batches = len(param_batches)
    content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), "").lower()
    
    for i, batch in enumerate(param_batches):
        log_prefix = f"[Phase 2 - Batch {i+1}/{total_batches}]"
        
        # Create unique marker for EACH parameter
        param_marker_map = {param: generate_random_string(12) for param in batch}
        
        request_data = None
        current_headers = headers.copy()
        
        # Build query params with markers
        batch_query_params = original_query_params.copy()
        for param, marker in param_marker_map.items():
            batch_query_params[param] = marker
        
        request_url = f"{base_path}?{urlencode(batch_query_params, doseq=True)}"
        
        if method.upper() == "POST":
            current_headers.pop('Content-Length', None)
            current_headers.pop('content-length', None)
            
            if 'application/x-www-form-urlencoded' in content_type:
                # ✅ CRITICAL FIX: Preserve original body as raw string
                try:
                    original_body_str = original_body_bytes.decode('utf-8', errors='ignore')
                except:
                    original_body_str = ""
                
                # Append test params to the end without parsing
                appended_params = "&".join([f"{quote(param, safe='')}={quote(marker, safe='')}" for param, marker in param_marker_map.items()])
                
                if original_body_str:
                    request_data = f"{original_body_str}&{appended_params}".encode('utf-8')
                else:
                    request_data = appended_params.encode('utf-8')
            
            elif 'multipart/form-data' in content_type:
                patched_body = original_body_bytes
                for param, marker in param_marker_map.items():
                    pattern = re.compile(
                        b'(--[^\r\n]+\r\nContent-Disposition: form-data; name="' + re.escape(param.encode()) + b'".*?\r\n\r\n)'
                        b'(.*?)(?=\r\n--)',
                        re.DOTALL
                    )
                    patched_body = pattern.sub(b'\\1' + marker.encode(), patched_body, count=1)
                request_data = patched_body
        
        response = await make_request_with_retries(
            target_url=request_url,
            headers=current_headers,
            log_prefix=log_prefix,
            method=method,
            data=request_data
        )
        
        if not response:
            await asyncio.sleep(DELAY_BETWEEN_BATCHES)
            continue
        
        color = C_GREEN if response.status_code == 200 else C_YELLOW
        console_logger.info(f"    {color}- Batch {i+1}/{total_batches} -> Status: {response.status_code}{C_END}")
        
        # Check if batch is suspicious
        response_text_unescaped = html.unescape(response.text)
        is_batch_suspicious = any(response_text_unescaped.count(marker) > baseline_count for marker in param_marker_map.values())
        
        if is_batch_suspicious:
            console_logger.info(f"    {C_BLUE}- Batch {i+1} is suspicious. Confirming individually...{C_END}")
            
            for param in batch:
                await asyncio.sleep(DELAY_BETWEEN_CONFIRMATIONS)
                
                individual_marker = generate_random_string(12)
                confirm_data = None
                confirm_headers = headers.copy()
                confirm_headers.pop('Content-Length', None)
                confirm_headers.pop('content-length', None)
                
                confirm_query_params = original_query_params.copy()
                confirm_query_params[param] = individual_marker
                confirm_url = f"{base_path}?{urlencode(confirm_query_params, doseq=True)}"
                
                if method.upper() == "POST":
                    if 'application/x-www-form-urlencoded' in content_type:
                        # ✅ SAME FIX: Keep raw body and append single test param
                        try:
                            original_body_str = original_body_bytes.decode('utf-8', errors='ignore')
                        except:
                            original_body_str = ""
                        
                        test_param = f"{quote(param, safe='')}={quote(individual_marker, safe='')}"
                        
                        if original_body_str:
                            confirm_data = f"{original_body_str}&{test_param}".encode('utf-8')
                        else:
                            confirm_data = test_param.encode('utf-8')
                    
                    elif 'multipart/form-data' in content_type:
                        confirm_body = original_body_bytes
                        pattern = re.compile(
                            b'(--[^\r\n]+\r\nContent-Disposition: form-data; name="' + re.escape(param.encode()) + b'".*?\r\n\r\n)'
                            b'(.*?)(?=\r\n--)',
                            re.DOTALL
                        )
                        confirm_body = pattern.sub(b'\\1' + individual_marker.encode(), confirm_body, count=1)
                        confirm_data = confirm_body
                
                confirm_response = await make_request_with_retries(
                    target_url=confirm_url,
                    headers=confirm_headers,
                    log_prefix=f"[Phase 2 - Confirm {param}]",
                    method=method,
                    data=confirm_data
                )
                
                if confirm_response:
                    confirm_text_unescaped = html.unescape(confirm_response.text)
                    confirm_count = confirm_text_unescaped.count(individual_marker)
                    
                    if confirm_count > baseline_count:
                        found_params.add(param)
                        console_logger.info(f"      {C_GREEN}[+] Confirmed reflected parameter: {param}{C_END}")
        
        await asyncio.sleep(DELAY_BETWEEN_BATCHES)
    
    return found_params








async def run_post_character_probe(base_url: str, headers: Dict, param: str, chars_to_test: List[str]) -> DefaultDict[str, List[str]]:
    results: DefaultDict[str, List[str]] = defaultdict(list)
    marker_start, marker_end = generate_random_string(3), generate_random_string(3)

    for content_type in ['urlencoded', 'multipart']:
        # --- PREFLIGHT CHECK ---
        preflight_marker = generate_random_string()
        preflight_log = f"[Phase 4 Preflight - {param} - {content_type}]"
        
        preflight_data, preflight_files = (None, None)
        if content_type == 'urlencoded':
            preflight_data = {param: preflight_marker}
        else: # multipart
            preflight_files = {param: (None, preflight_marker)}
            
        preflight_response = await make_request_with_retries(base_url, headers, preflight_log, method="POST", data=preflight_data, files=preflight_files)
        
        if not preflight_response or preflight_marker not in html.unescape(preflight_response.text):
            status = preflight_response.status_code if preflight_response else "N/A"
            console_logger.warning(f"    {C_YELLOW}[-] POST Preflight for '{param}' ({content_type}) failed (Status: {status}, No Reflection). Skipping full scan.{C_END}")
            continue # Skip to the next content_type
        
        console_logger.info(f"    {C_GREEN}[*] POST Preflight for '{param}' ({content_type}) successful. Proceeding with character scan.{C_END}")
        # --- END PREFLIGHT CHECK ---

        for char in chars_to_test:
            for encoding_name, encoded_value in ENCODING_MAP[char].items():
                payload_value = f"{marker_start}{encoded_value}{marker_end}"
                
                post_data, post_files = (None, None)
                if content_type == 'urlencoded':
                    post_data = {param: payload_value}
                else: # multipart
                    post_files = {param: (None, payload_value)}
                
                log_prefix = f"[Phase 4 - {param} - '{char}' - {content_type} - {encoding_name}]"
                response = await make_request_with_retries(base_url, headers, log_prefix, method="POST", data=post_data, files=post_files)
                
                if response and is_reflection_in_unsafe_context(response.text, marker_start, marker_end, char):
                    method = f"post-{content_type}:{encoding_name}"
                    results[char].append(method)
                    console_logger.info(f"      {C_GREEN}[POST SUCCESS] Reflected '{C_YELLOW}{char}{C_GREEN}' via {content_type} with encoding '{C_YELLOW}{encoding_name}{C_GREEN}'!{C_END}")
                    if encoding_name == 'raw':
                        break # Skip other encodings for this char if raw works
    return results


async def analyze_single_param(
    base_url: str,
    headers: dict,
    param: str,
    original_method: str = "GET",
    original_body_bytes: bytes = b"",
    original_full_url: str = ""  # ✅ NEW: Full URL with all query params
):
    """
    Analyze a single parameter through Phase 3 and Phase 4.
    KEY FIX: Preserves ALL original query parameters during character testing.
    """
    all_param_bypasses = defaultdict(list)
    original_method = original_method.upper()

    # Detect original content-type
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
    is_multipart = "multipart/form-data" in content_type
    is_urlencoded = "application/x-www-form-urlencoded" in content_type

    # ========== PHASE 3 ==========
    console_logger.info(f"  {C_CYAN}[Phase 3] Probing {original_method} for param '{param}'...{C_END}")

    if original_method == "GET":
        # ✅ FIXED: Pass original_full_url to preserve all query params
        get_bypass_results = await run_character_probe(
            base_url=base_url,
            headers=headers,
            param=param,
            original_full_url=original_full_url  # ✅ NEW PARAMETER
        )
        for char, methods in get_bypass_results.items():
            all_param_bypasses[char].extend(methods)

        not_bypassed_by_get = [c for c in PROBE_CHARS if not get_bypass_results.get(c)]

        if not not_bypassed_by_get:
            console_logger.info(
                f"    {C_GREEN}[Phase 3 COMPLETE] All probe chars bypassed via GET for '{param}'. Skipping POST.{C_END}"
            )
        else:
            console_logger.info(
                f"    {C_YELLOW}[Phase 4] Running POST fallback for '{param}' on chars: {', '.join(not_bypassed_by_get)}{C_END}"
            )

            # 1. Try URL-encoded fallback
            post_urlencoded_results = await run_post_character_probe_with_body(
                base_url=base_url,
                headers=headers,
                param=param,
                chars_to_test=not_bypassed_by_get,
                original_body_bytes=original_body_bytes,
            )
            for char, methods in post_urlencoded_results.items():
                all_param_bypasses[char].extend(methods)

            not_bypassed_after_urlencoded = [
                c for c in not_bypassed_by_get if not post_urlencoded_results.get(c)
            ]

            if not_bypassed_after_urlencoded:
                console_logger.info(
                    f"    {C_YELLOW}[Phase 4] Trying multipart for remaining: {', '.join(not_bypassed_after_urlencoded)}{C_END}"
                )
                # 2. Try Multipart fallback
                multipart_results = await run_post_character_probe_multipart(
                    base_url=base_url,
                    headers=headers,
                    param=param,
                    chars_to_test=not_bypassed_after_urlencoded,
                    original_body_bytes=original_body_bytes,
                )
                for char, methods in multipart_results.items():
                    all_param_bypasses[char].extend(methods)

    else:
        # POST request logic
        chars_to_test = PROBE_CHARS

        if is_urlencoded:
            console_logger.info(f"    {C_BLUE}[Phase 3] Original POST was urlencoded.{C_END}")
            # 1. Run URL-encoded probe
            primary_results = await run_post_character_probe_with_body(
                base_url=base_url,
                headers=headers,
                param=param,
                chars_to_test=chars_to_test,
                original_body_bytes=original_body_bytes,
            )
            for char, methods in primary_results.items():
                all_param_bypasses[char].extend(methods)

            not_bypassed = [c for c in chars_to_test if not primary_results.get(c)]

            if not_bypassed:
                console_logger.info(
                    f"    {C_YELLOW}[Phase 4] Urlencoded failed for: {', '.join(not_bypassed)} → trying multipart.{C_END}"
                )
                # 2. Run Multipart fallback
                fallback_results = await run_post_character_probe_multipart(
                    base_url=base_url,
                    headers=headers,
                    param=param,
                    chars_to_test=not_bypassed,
                    original_body_bytes=original_body_bytes,
                )
                for char, methods in fallback_results.items():
                    all_param_bypasses[char].extend(methods)
            
        elif is_multipart:
            console_logger.info(f"    {C_BLUE}[Phase 3] Original POST was multipart.{C_END}")
            # 1. Run Multipart probe
            primary_results = await run_post_character_probe_multipart(
                base_url=base_url,
                headers=headers,
                param=param,
                chars_to_test=chars_to_test,
                original_body_bytes=original_body_bytes,
            )
            for char, methods in primary_results.items():
                all_param_bypasses[char].extend(methods)

            not_bypassed = [c for c in chars_to_test if not primary_results.get(c)]

            if not_bypassed:
                console_logger.info(
                    f"    {C_YELLOW}[Phase 4] Multipart failed for: {', '.join(not_bypassed)} → trying urlencoded.{C_END}"
                )
                # 2. Run URL-encoded fallback
                fallback_results = await run_post_character_probe_with_body(
                    base_url=base_url,
                    headers=headers,
                    param=param,
                    chars_to_test=not_bypassed,
                    original_body_bytes=original_body_bytes,
                )
                for char, methods in fallback_results.items():
                    all_param_bypasses[char].extend(methods)

        else:
            console_logger.info(f"    {C_YELLOW}[Phase 3] Unknown POST type, defaulting to urlencoded first.{C_END}")
            # 1. Run URL-encoded probe (Default)
            post_bypass_results = await run_post_character_probe_with_body(
                base_url=base_url,
                headers=headers,
                param=param,
                chars_to_test=chars_to_test,
                original_body_bytes=original_body_bytes,
            )
            for char, methods in post_bypass_results.items():
                all_param_bypasses[char].extend(methods)

            not_bypassed = [c for c in chars_to_test if not post_bypass_results.get(c)]

            if not_bypassed:
                console_logger.info(
                    f"    {C_YELLOW}[Phase 4] Trying multipart for: {', '.join(not_bypassed)}{C_END}"
                )
                # 2. Run Multipart fallback
                multipart_results = await run_post_character_probe_multipart(
                    base_url=base_url,
                    headers=headers,
                    param=param,
                    chars_to_test=not_bypassed,
                    original_body_bytes=original_body_bytes,
                )
                for char, methods in multipart_results.items():
                    all_param_bypasses[char].extend(methods)

    # ========== SUMMARY ==========
    if all_param_bypasses:
        # Sort results for clean summary
        sorted_chars = sorted(all_param_bypasses.keys(), key=lambda c: PROBE_CHARS.index(c) if c in PROBE_CHARS else 99)
        summary = " | ".join(
            [f"'{c}': {', '.join(all_param_bypasses[c])}" for c in sorted_chars]
        )
        console_logger.info(
            f"    {C_RED}[VULN SUMMARY] '{param}' reflects: {summary}{C_END}"
        )
        await send_summary_discord_notification(base_url, param, all_param_bypasses)
    else:
        console_logger.info(f"  {C_YELLOW}[-] No bypasses for '{param}'.{C_END}")



# In processor_server.py
# REPLACE your entire run_post_character_probe_with_body function with this FIXED version

async def run_post_character_probe_with_body(
    base_url: str,
    headers: Dict,
    param: str,
    chars_to_test: List[str],
    original_body_bytes: bytes
) -> DefaultDict[str, List[str]]:
    """
    ✅ FIXED: Manually parses body to preserve EXACT encoding structure.
    Preserves nested parameters like urls[0][longUrl] correctly.
    """
    from urllib.parse import unquote, quote
    
    successful_bypasses: DefaultDict[str, List[str]] = defaultdict(list)
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()

    # Using natural markers to avoid WAF detection
    marker_start = generate_natural_marker("val")
    marker_end = generate_natural_marker("end")

    # ✅ Parse original body as RAW string (no urlencode/decode)
    try:
        original_body_str = original_body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        original_body_str = ""

    console_logger.debug(f"  [DEBUG] Original body (first 300 chars): {original_body_str[:300]}")

    for char in chars_to_test:
        console_logger.debug(f"\n  [DEBUG] Testing character: '{char}'")
        
        for encoding_name, encoded_value in ENCODING_MAP[char].items():
            await asyncio.sleep(DELAY_BETWEEN_PROBES)
            
            console_logger.debug(f"  [DEBUG] Encoding: {encoding_name}")
            console_logger.debug(f"  [DEBUG] Encoded value: {encoded_value}")
            
            payload_value = f"{marker_start}{encoded_value}{marker_end}"
            console_logger.debug(f"  [DEBUG] Full payload: {payload_value}")

            # Prepare headers
            post_headers = headers.copy()
            post_headers.pop("Content-Length", None)
            post_headers.pop("content-length", None)

            # ✅ Referer integrity check
            ref_found = any(k.lower() == "referer" for k in post_headers.keys())
            if not ref_found:
                parsed = urlparse(base_url)
                forced_ref = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                post_headers["Referer"] = forced_ref
                console_logger.debug(f"    [REFERER-FIX] Added referer: {forced_ref}")

            if "user-agent" not in [k.lower() for k in post_headers.keys()]:
                post_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

            # ✅✅✅ CRITICAL FIX: Manual body reconstruction to preserve encoding ✅✅✅
            if "application/x-www-form-urlencoded" in content_type or original_body_str:
                try:
                    # Split by '&' and rebuild parameter by parameter
                    body_parts = []
                    param_found = False
                    
                    for param_pair in original_body_str.split('&'):
                        if not param_pair:
                            continue
                        
                        if '=' not in param_pair:
                            body_parts.append(param_pair)
                            continue
                        
                        # Split ONLY on first '=' to preserve nested structures
                        key_encoded, value = param_pair.split('=', 1)
                        
                        # Decode ONLY the key for comparison
                        try:
                            key_decoded = unquote(key_encoded, errors='ignore')
                        except Exception:
                            key_decoded = key_encoded
                        
                        if key_decoded == param:
                            # ✅ Found our target parameter!
                            param_found = True
                            # ALWAYS use the original encoded key
                            final_key = key_encoded
                            # Encode the payload value appropriately
                            final_value = quote(payload_value, safe='')

                            body_parts.append(f"{final_key}={final_value}")
                            console_logger.debug(f"  [DEBUG] Replaced '{key_decoded}' with payload.")

                        else:
                            # Keep original parameter untouched
                            body_parts.append(param_pair)
                    
                    if not param_found:
                        # Parameter not in body, add it
                        # a new parameter should be fully encoded
                        final_key = quote(param, safe='')
                        final_value = quote(payload_value, safe='')
                        body_parts.append(f"{final_key}={final_value}")
                        console_logger.debug(f"  [DEBUG] Added new param '{param}' with payload.")

                    
                    post_data = '&'.join(body_parts).encode('utf-8')
                    console_logger.debug(f"  [DEBUG] Final body (first 300 chars): {post_data[:300]}")
                    
                except Exception as e:
                    console_logger.debug(f"    [DEBUG] Failed to parse body: {e}. Using fallback.")
                    # Fallback: simple encoding
                    post_data = urlencode({param: payload_value}).encode("utf-8")
            else:
                # No original body, create simple param
                post_data = urlencode({param: payload_value}).encode("utf-8")
                post_headers["Content-Type"] = "application/x-www-form-urlencoded"

            log_prefix = f"[Phase 3/4 POST-urlencoded - {param} - '{char}' - {encoding_name}]"

            # Send request
            response = await make_request_with_retries(
                target_url=base_url,
                headers=post_headers,
                method="POST",
                log_prefix=log_prefix,
                data=post_data,
            )

            if not response:
                console_logger.debug(f"  [DEBUG] No response received")
                continue

            # ✅ Use the CORRECT reflection checker
            if is_reflection_in_unsafe_context(response.text, marker_start, marker_end, char):
                method = f"post-urlencoded:{encoding_name}"
                successful_bypasses[char].append(method)
                console_logger.info(
                    f"      {C_GREEN}[POST SUCCESS] Reflected '{C_YELLOW}{char}{C_GREEN}' via urlencoded with encoding '{C_YELLOW}{encoding_name}{C_GREEN}'!{C_END}"
                )
                # Optimization: if raw works, skip other encodings
                if encoding_name == "raw":
                    break
            else:
                console_logger.debug(f"  [DEBUG] ❌ Marker not found in response")

    console_logger.debug(f"\n{'='*80}")
    console_logger.debug(f"[RESULTS] Param '{param}' completed: {len(successful_bypasses)} characters bypassed")
    console_logger.debug(f"{'='*80}\n")

    return successful_bypasses






# -----------------------------------------------------------------------------------

async def run_character_probe(
    base_url: str,
    headers: Dict,
    param: str,
    original_full_url: str
) -> DefaultDict[str, List[str]]:
    """
    ✅ FIXED: Preserves all original query parameters.
    """
    from urllib.parse import parse_qsl, urlencode
    
    successful_bypasses: DefaultDict[str, List[str]] = defaultdict(list)
    marker_start, marker_end = generate_random_string(3), generate_random_string(3)

    # ✅ Parse original URL to extract ALL query parameters
    parsed_url = urlparse(original_full_url)
    base_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    # ✅ Use parse_qsl to preserve order and duplicates
    original_params = parse_qsl(parsed_url.query, keep_blank_values=True)

    console_logger.debug(f"  [DEBUG] Original params: {original_params}")

    for char in PROBE_CHARS:
        for encoding_name, encoded_char in ENCODING_MAP[char].items():
            payload_value = f"{marker_start}{encoded_char}{marker_end}"

            # ✅ Rebuild params: update target param, keep others
            test_params = []
            param_found = False
            
            for key, value in original_params:
                if key == param:
                    test_params.append((key, payload_value))
                    param_found = True
                else:
                    test_params.append((key, value))
            
            if not param_found:
                test_params.append((param, payload_value))

            # ✅ Rebuild URL
            req_url = f"{base_path}?{urlencode(test_params)}"

            log_prefix = f"[Phase 3 GET - {param} - '{char}' - {encoding_name}]"
            console_logger.debug(f"  [DEBUG] Sending GET: {req_url}")

            response = await make_request_with_retries(req_url, headers, log_prefix)

            if response and is_reflection_in_unsafe_context(response.text, marker_start, marker_end, char):
                method = f"get:{encoding_name}"
                successful_bypasses[char].append(method)
                console_logger.info(
                    f"      {C_GREEN}[GET SUCCESS] Reflected '{C_YELLOW}{char}{C_GREEN}' with encoding '{C_YELLOW}{encoding_name}{C_GREEN}'!{C_END}"
                )
                if encoding_name == "raw":
                    break

            await asyncio.sleep(DELAY_BETWEEN_PROBES)

    return successful_bypasses







async def run_post_character_probe_multipart(
    base_url: str,
    headers: dict,
    param: str,
    chars_to_test: list,
    original_body_bytes: bytes
) -> dict:
    """
    Probes POST requests with multipart body.
    Tests ALL encodings just like run_character_probe does.
    """
    successful_bypasses: DefaultDict[str, List[str]] = defaultdict(list)
    
    # Generate markers once for consistency
    marker_start, marker_end = generate_random_string(3), generate_random_string(3)
    
    for char in chars_to_test:
        for encoding_name, encoded_value in ENCODING_MAP[char].items():
            await asyncio.sleep(DELAY_BETWEEN_PROBES)
            
            # Build the payload with proper markers
            payload_value = f"{marker_start}{encoded_value}{marker_end}"
            
            post_headers = headers.copy()
            post_headers.pop('Content-Length', None)
            post_headers.pop('content-length', None)
            
            # Build multipart body
            boundary = '----WebKitFormBoundary' + generate_random_string(16)
            post_data = f'--{boundary}\r\n'
            post_data += f'Content-Disposition: form-data; name="{param}"\r\n\r\n'
            post_data += f'{payload_value}\r\n'
            post_data += f'--{boundary}--\r\n'
            
            post_headers['Content-Type'] = f'multipart/form-data; boundary={boundary}'
            
            log_prefix = f"[Phase 4 Multipart - {param} - '{char}' - {encoding_name}]"
            response = await make_request_with_retries(
                target_url=base_url,
                headers=post_headers,
                log_prefix=log_prefix,
                method="POST",
                data=post_data.encode('utf-8')
            )
            
            # Use the proper reflection detection function
            if response and is_reflection_in_unsafe_context(response.text, marker_start, marker_end, char):
                method = f"post-multipart:{encoding_name}"
                successful_bypasses[char].append(method)
                console_logger.info(f"      {C_GREEN}[POST SUCCESS] Reflected '{C_YELLOW}{char}{C_GREEN}' via multipart with encoding '{C_YELLOW}{encoding_name}{C_GREEN}'!{C_END}")
                
                # If raw reflection works, skip other encodings for this char
                if encoding_name == 'raw':
                    break
    
    return successful_bypasses


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_parameters_from_file(); yield
    console_logger.info(f"{C_RED}[*] Server shutting down.{C_END}")

app = FastAPI(lifespan=lifespan)

# Add this helper function somewhere above process_single_request
async def discover_params_from_response(base_url: str, headers: Dict) -> Set[str]:
    """
    Makes a request to the base URL and scrapes the response body for potential
    parameter names using regular expressions.
    """
    found_params = set()
    log_prefix = "[Phase 0 - Response Analysis]"
    
    # Make a single, clean request to the target URL to get its content
    response = await make_request_with_retries(base_url, headers, log_prefix)
    
    if not response:
        console_logger.error(f"    {C_RED}{log_prefix} Failed to fetch response from {base_url}.{C_END}")
        return found_params

    text = html.unescape(response.text)

    PARAM_REGEX = re.compile(r"['\"]([a-zA-Z0-9_\[\]-]{3,25})['\"]\s*[:=]")
    
    try:
        matches = PARAM_REGEX.findall(text)
        if matches:
            found_params.update(matches)
    except Exception as e:
        console_logger.error(f"    {C_RED}{log_prefix} Error during regex matching: {e}{C_END}")

    return found_params


async def run_canary_global_reflection_test(base_url: str, headers: Dict, params_to_test: List[str]) -> tuple[int, Set[str]]:
    """
    Canary test: Send 40 different parameters with unique random values.
    Measure how many times each value appears in the response.
    If a parameter's value is reflected MORE than the global baseline, it's a true reflection.
    
    Returns: (global_baseline_count, set_of_truly_reflected_params)
    """
    console_logger.info(f"  {C_CYAN}[Canary Test] Testing global reflection pattern with {len(params_to_test)} unique parameters...{C_END}")
    
    # Take first 40 params and generate unique marker for each
    test_params = params_to_test[:40]
    param_marker_map = {param: generate_random_string(12) for param in test_params}
    
    # Build URL with all parameters
    parsed_url = urlparse(base_url)
    base_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    query_params = {param: marker for param, marker in param_marker_map.items()}
    request_url = f"{base_path}?{urlencode(query_params, doseq=True)}"
    
    # Make request
    response = await make_request_with_retries(
        target_url=request_url,
        headers=headers,
        log_prefix="[Canary Test]",
        method="GET"
    )
    
    if not response:
        console_logger.warning(f"  {C_YELLOW}[Canary Test] Failed to get response. Assuming no global reflection.{C_END}")
        return 0, set()
    
    response_text = html.unescape(response.text)
    
    # Count reflections for each marker
    reflection_counts = {}
    for param, marker in param_marker_map.items():
        count = response_text.count(marker)
        reflection_counts[param] = count
    
    # Calculate global baseline (minimum non-zero reflection)
    non_zero_counts = [c for c in reflection_counts.values() if c > 0]
    
    if not non_zero_counts:
        console_logger.info(f"  {C_YELLOW}[Canary Test] No reflections detected at all.{C_END}")
        return 0, set()
    
    # Use minimum non-zero as global baseline
    global_baseline = min(non_zero_counts)
    
    # Find parameters reflected MORE than global baseline
    truly_reflected = {
        param for param, count in reflection_counts.items() 
        if count > global_baseline
    }
    
    console_logger.info(f"  {C_BLUE}[Canary Test] Global baseline reflection: {global_baseline}{C_END}")
    console_logger.info(f"  {C_BLUE}[Canary Test] Parameters reflected MORE than baseline: {len(truly_reflected)}{C_END}")
    
    if truly_reflected:
        console_logger.info(f"    {C_GREEN}[+] Truly reflected params: {', '.join(sorted(truly_reflected))}{C_END}")
    
    # Log detailed reflection counts
    for param, count in sorted(reflection_counts.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            color = C_GREEN if count > global_baseline else C_YELLOW
            console_logger.info(f"      {color}- {param}: {count} reflections{C_END}")
    
    return global_baseline, truly_reflected

async def run_sequential_discovery(
    full_url: str,
    method: str,
    headers: Dict,
    original_body_bytes: bytes,
    baseline_count: int,
    params_to_test: List[str]
) -> Set[str]:
    """
    ✅ FIXED: Handles both plain and encoded parameter names correctly
    """
    console_logger.info(
        f"  {C_BLUE}[Sequential Discovery] Testing {len(params_to_test)} parameters individually...{C_END}"
    )

    parsed_url = urlparse(full_url)
    base_path = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    original_query_params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    content_type = headers.get('Content-Type', headers.get('content-type', '')).lower()
    
    # Parse original body
    original_body_str = ""
    if method.upper() == "POST" and original_body_bytes:
        try:
            original_body_str = original_body_bytes.decode('utf-8', errors='ignore')
        except Exception:
            original_body_str = ""

    reflected_params = set()

    # ========================================
    # ✅ Test each parameter INDIVIDUALLY
    # ========================================
    for idx, param in enumerate(params_to_test, 1):
        await asyncio.sleep(DELAY_BETWEEN_CONFIRMATIONS)
        
        # Generate unique marker for THIS parameter
        unique_marker = generate_random_string(12)
        
        console_logger.info(
            f"    {C_YELLOW}[{idx}/{len(params_to_test)}] Testing parameter: {param} "
            f"(marker: {unique_marker}){C_END}"
        )

        # ========================================
        # Build request with ALL params preserved
        # ========================================
        test_query_params = original_query_params.copy()
        # ✅ CRITICAL FIX: Always start with the original body.
        # This ensures that when we test a query parameter, the POST body is not dropped.
        test_data = original_body_bytes
        test_headers = headers.copy()
        test_headers.pop('Content-Length', None)
        test_headers.pop('content-length', None)

        # ✅ CRITICAL FIX: Check if param exists in query (both plain and encoded forms)
        param_decoded = unquote(param)
        param_in_query = (param in original_query_params) or (param_decoded in original_query_params)
        param_in_body = False
        
        if method.upper() == "POST" and original_body_str:
            # ✅ Check BOTH encoded and decoded forms in body
            param_in_body = f"{param}=" in original_body_str or f"{param_decoded}=" in unquote(original_body_str)

        # ========================================
        # Build Query String
        # ========================================
        if param_in_query:
            # ✅ Try both forms
            if param in original_query_params:
                test_query_params[param] = [unique_marker]
            elif param_decoded in original_query_params:
                test_query_params[param_decoded] = [unique_marker]
        elif not param_in_body:
            # Add to query (use decoded form for new params)
            test_query_params[param_decoded] = [unique_marker]

        test_url = f"{base_path}?{urlencode(test_query_params, doseq=True)}"

        # ========================================
        # Build POST Body (if POST request)
        # ========================================
        if method.upper() == "POST" and param_in_body:
            if 'application/x-www-form-urlencoded' in content_type:
                try:
                    body_parts = []
                    param_replaced = False

                    # ✅ CRITICAL FIX: Match BOTH encoded and decoded forms
                    for param_pair in original_body_str.split('&'):
                        if not param_pair:
                            continue

                        if '=' not in param_pair:
                            body_parts.append(param_pair)
                            continue

                        # Split on first '=' to preserve nested structures
                        key_part, value_part = param_pair.split('=', 1)

                        # ✅ Compare BOTH encoded and decoded forms
                        key_decoded_check = unquote(key_part)
                        
                        if key_part == param or key_decoded_check == param or key_decoded_check == param_decoded:
                            # ✅ Replace with marker (keep original encoding)
                            body_parts.append(f"{key_part}={quote(unique_marker, safe='')}")
                            param_replaced = True
                            console_logger.debug(f"      [DEBUG] Replaced '{key_part}' with marker")
                        else:
                            # ✅ Keep ALL other params UNCHANGED
                            body_parts.append(param_pair)

                    if not param_replaced:
                        # Param not found, add it (use encoded form if available)
                        console_logger.debug(f"      [DEBUG] Parameter '{param}' not found in body, adding it")
                        body_parts.append(f"{quote(param_decoded, safe='')}={quote(unique_marker, safe='')}")

                    test_data = "&".join(body_parts).encode('utf-8')
                    
                    console_logger.debug(f"      [DEBUG] Final body length: {len(test_data)} bytes")

                except Exception as e:
                    console_logger.error(f"  [ERROR] Failed to build body for {param}: {e}")
                    continue

            elif 'multipart/form-data' in content_type:
                # For multipart, try both forms
                patched_body = original_body_bytes
                
                # Try encoded form first
                pattern1 = re.compile(
                    b'(--[^\r\n]+\r\nContent-Disposition: form-data; name="' + 
                    re.escape(param.encode()) + b'".*?\r\n\r\n)'
                    b'(.*?)(?=\r\n--)',
                    re.DOTALL
                )
                patched_body = pattern1.sub(b'\\1' + unique_marker.encode(), patched_body, count=1)
                
                # Try decoded form if first didn't match
                if patched_body == original_body_bytes:
                    pattern2 = re.compile(
                        b'(--[^\r\n]+\r\nContent-Disposition: form-data; name="' + 
                        re.escape(param_decoded.encode()) + b'".*?\r\n\r\n)'
                        b'(.*?)(?=\r\n--)',
                        re.DOTALL
                    )
                    patched_body = pattern2.sub(b'\\1' + unique_marker.encode(), patched_body, count=1)
                
                test_data = patched_body

        # ========================================
        # Make Request
        # ========================================
        log_prefix = f"[Sequential Test {idx}/{len(params_to_test)} - {param}]"
        
        response = await make_request_with_retries(
            target_url=test_url,
            headers=test_headers,
            log_prefix=log_prefix,
            method=method,
            data=test_data
        )

        if not response:
            continue

        # ========================================
        # Check Reflection
        # ========================================
        response_text_unescaped = html.unescape(response.text)
        reflection_count = response_text_unescaped.count(unique_marker)

        if reflection_count > baseline_count:
            console_logger.info(
                f"      {C_GREEN}[✓ REFLECTED] Parameter '{param}' reflected "
                f"{reflection_count} times (baseline: {baseline_count})!{C_END}"
            )
            reflected_params.add(param)
        else:
            console_logger.debug(
                f"      {C_YELLOW}[✗] Parameter '{param}' NOT reflected "
                f"({reflection_count} times, baseline: {baseline_count}){C_END}"
            )

    return reflected_params



async def process_single_request(item: RequestItem):
    """
    Process a single request from Burp through all phases.
    ✅ FIXED: Preserves full URL including query strings for POST requests.
    ✅ FIXED: Uses retry wrapper for Phase 2.1 and 2.2
    """
    parsed_url = urlparse(item.url)
    
    # ✅ CRITICAL FIX: Keep FULL URL (including query string) for POST
    if item.method.upper() == "POST":
        base_url = item.url  # Preserves ?cmd=ajax and other query params
    else:
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    original_headers = headers_list_to_dict(item.headers)
    params_from_request_keys = set(parse_qs(parsed_url.query).keys())
    content_type = next((v for k, v in original_headers.items() if k.lower() == 'content-type'), "").lower()

    if item.method.upper() == 'POST' and item.body:
        if 'application/x-www-form-urlencoded' in content_type:
            try:
                body_str = item.body.decode('utf-8', 'ignore')
                # Manual parsing to preserve original encoded parameter names
                for param_pair in body_str.split('&'):
                    if '=' in param_pair:
                        key = param_pair.split('=', 1)[0]
                        # We now add the DECODED key, so it can be consistently
                        # matched by the testing functions, which expect decoded names.
                        # The functions that reconstruct the request are already
                        # designed to handle re-encoding the parameter correctly.
                        params_from_request_keys.add(unquote(key))
            except Exception as e:
                console_logger.error(f"    {C_RED}[!] Error parsing urlencoded POST body: {e}{C_END}")
        
        elif 'multipart/form-data' in content_type:
            try:
                body_file = io.BytesIO(item.body)
                headers_for_cgi = {'content-type': content_type}
                form_data = cgi.FieldStorage(fp=body_file, headers=headers_for_cgi, environ={'REQUEST_METHOD': 'POST'})
                if form_data.list:
                    params_from_request_keys.update(field.name for field in form_data.list if field.name)
            except Exception as e:
                console_logger.error(f"    {C_RED}[!] Error parsing multipart POST body with cgi: {e}{C_END}")

    param_signature = ",".join(sorted(list(params_from_request_keys)))
    unique_request_key = f"{item.method.upper()}:{base_url}:{param_signature}"

    async with processed_urls_lock:
        if unique_request_key in PROCESSED_URLS:
            console_logger.info(f"{C_YELLOW}[-] Skipping duplicate request signature: {unique_request_key}{C_END}")
            return
        PROCESSED_URLS.add(unique_request_key)

    console_logger.info(f"\n{C_MAGENTA}[+] Processing Target: {item.method} {item.url}{C_END}")

    forwarded_headers = {"User-Agent": "Mozilla/5.0"}
    for key, value in original_headers.items():
        if key.lower() not in HEADER_BLACKLIST:
            forwarded_headers[key] = value

    # Phase 0: Discover potential params from response body
    console_logger.info(f"  {C_BLUE}[*] Phase 0: Discovering potential params from response body...{C_END}")
    params_from_response = await discover_params_from_response(base_url, forwarded_headers)
    if params_from_response:
        console_logger.info(f"    {C_GREEN}[SUCCESS] Discovered {len(params_from_response)} potential new parameters from the response.{C_END}")
    else:
        console_logger.info(f"    {C_YELLOW}[-] No new parameters discovered in the response body.{C_END}")
    
    params_from_request = params_from_request_keys
    
    # Phase 1: Establish a reliable reflection baseline.
    baseline_count = await establish_reflection_baseline(
        full_url=item.url,
        method=item.method,
        headers=forwarded_headers,
        original_body_bytes=item.body
    )

    all_reflected_params = set()

    # Phase 2.1: Prioritize parameters from the original request and response
    params_from_context = list(params_from_request.union(params_from_response))
    if params_from_context:
        console_logger.info(f"  {C_BLUE}[*] Phase 2.1: Sequentially testing {len(params_from_context)} parameters from request/response...{C_END}")

        request_reflected_params = await run_sequential_discovery(
            full_url=item.url,
            method=item.method,
            headers=forwarded_headers,
            original_body_bytes=item.body,
            baseline_count=baseline_count,
            params_to_test=params_from_context
        )

        if request_reflected_params:
            console_logger.info(f"    {C_GREEN}[SUCCESS] Found {len(request_reflected_params)} reflected parameters from request: {', '.join(sorted(list(request_reflected_params)))}{C_END}")
            all_reflected_params.update(request_reflected_params)

    # Phase 2.2: Discover additional parameters using the wordlist
    params_to_bruteforce = [p for p in PARAMS_TO_TEST if p not in all_reflected_params]
    if params_to_bruteforce:
        console_logger.info(f"  {C_BLUE}[*] Phase 2.2: Batch testing {len(params_to_bruteforce)} parameters from wordlist...{C_END}")

        # Use the batched discovery (with retries) for the larger wordlist
        wordlist_reflected_params = await run_batched_discovery_with_retry(
            full_url=item.url,
            method=item.method,
            headers=forwarded_headers,
            original_body_bytes=item.body,
            baseline_count=baseline_count,
            params_to_test=params_to_bruteforce
        )

        if wordlist_reflected_params:
            # Convert list to set for update operation
            wordlist_param_set = set(wordlist_reflected_params)
            console_logger.info(f"    {C_GREEN}[SUCCESS] Found {len(wordlist_param_set)} additional reflected parameters from wordlist.{C_END}")
            all_reflected_params.update(wordlist_param_set)

    # Final Check and Continuation
    if not all_reflected_params:
        console_logger.info(f"{C_YELLOW}[-] No reflected parameters found for {base_url} in any phase.{C_END}")
        return

    console_logger.info(f"{C_GREEN}[Phase 2 COMPLETE] Found a total of {len(all_reflected_params)} reflected parameters: {', '.join(sorted(list(all_reflected_params)))}{C_END}")

    # Concurrent Analysis (Phase 3 & 4)
    analysis_tasks = [
        analyze_single_param(
            base_url=base_url,
            headers=forwarded_headers,
            param=param,
            original_method=item.method,
            original_body_bytes=item.body,
            original_full_url=item.url
        )
        for param in sorted(list(all_reflected_params))
    ]
    await asyncio.gather(*analysis_tasks)




@app.post("/process")
async def process_requests_batch(batch: RequestBatch, background_tasks: BackgroundTasks):
    for item in batch.requests:
        try:
            # CRITICAL CHANGE: Decode body from Base64 string to raw bytes.
            # We no longer decode it to a UTF-8 string here.
            item.body = base64.b64decode(item.body)
        except (binascii.Error, TypeError) as e:
            # Added TypeError for safety if item.body is not a string-like type
            console_logger.warning(f"  [!] Base64 decoding failed for a request body: {e}")
            item.body = b""  # Default to empty bytes on failure

        # Pass the item with the raw bytes body to the next function.
        background_tasks.add_task(process_single_request, item)

    return {"status": "ok", "message": f"Processing {len(batch.requests)} requests in the background."}


if __name__ == "__main__":
    console_logger.info(f"{C_BLUE}[*] Hunter's XSS Server (v15.0) starting on http://0.0.0.0:8088{C_END}")
    uvicorn.run(app, host="0.0.0.0", port=8088, log_config=None)
