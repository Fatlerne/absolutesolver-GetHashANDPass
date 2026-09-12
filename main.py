import base64
import hashlib
import importlib.util
import os
import sys
import time
from collections import deque
from itertools import product
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED

from Crypto.Cipher import AES

# ============================================================
#  TEMPLATE config.py — will be created if the file does not exist.
# ============================================================
DEFAULT_CONFIG_TEXT = '''\
# ============================================================
#  PASSWORD GENERATION CONFIG (created automatically)
#  Fill in ALL the fields below (empty values will result in an error).
# ============================================================

# ---------- HASH 1 ----------
SALT_B64_1       = ""
NONCE_B64_1      = ""
CIPHERTEXT_B64_1 = ""
AUTH_TAG_B64_1   = ""

# ---------- HASH 2 ----------
SALT_B64_2       = ""
NONCE_B64_2      = ""
CIPHERTEXT_B64_2 = ""
AUTH_TAG_B64_2   = ""

# ---------- HASH 3 ----------
SALT_B64_3       = ""
NONCE_B64_3      = ""
CIPHERTEXT_B64_3 = ""
AUTH_TAG_B64_3   = ""

# ---------- PARAMETERS KDF ----------
# ITERATIONS — a positive integer (for example, 2100000)
# DKLEN      — a positive integer (for example, 32)
ITERATIONS = 0
DKLEN      = 0

# ---------- LOGS ----------
LOG1 = "fail_pass.log"
LOG2 = "fail_pass2.log"
LOG3 = "fail_pass3.log"

# ---------- EFFICIENCY ----------
# MAX_WORKERS = 0  ->  auto (os.cpu_count())
MAX_WORKERS              = 0
POLL_TIMEOUT             = 0.05
INTERRUPT_CONFIRM_WINDOW = 5.0
WARNING_DURATION         = 5.0

# ============================================================
#  PASSWORD PARTS ARRAYS
#  The final password = concatenation of one part from each array
#  (Cartesian product). Each array must be non-empty.
# ============================================================
arr1 = []
arr2 = []
arr3 = []
arr4 = []
arr5 = []
arr6 = []

ARRAYS = [arr1, arr2, arr3, arr4, arr5, arr6]

# The minimum length of the final password
MIN_PASSWORD_LEN = 6
'''

# ============================================================
#  CONFIG LOADING AND VALIDATION
# ============================================================
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.py")

def ensure_config(path=CONFIG_PATH):
    """If config.py is not present, it creates a template and terminates. Otherwise, it imports it."""
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_CONFIG_TEXT)
        except OSError as e:
            print(f"❌ It was not possible to create {path}: {e}")
            sys.exit(1)
        print(f"[i] The config.py file was not found — a template was created: {path}")
        print("[i] Fill in the fields (hashes, ITERATIONS, DKLEN, arrays) and run main.py again.")
        sys.exit(0)

    spec = importlib.util.spec_from_file_location("config", path)
    if spec is None or spec.loader is None:
        print(f"❌ Failed to load {path}")
        sys.exit(1)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        print(f"❌ Error while importing config.py: {e}")
        sys.exit(1)
    return module


def _is_nonempty_str(v):
    return isinstance(v, str) and v.strip() != ""


def _is_positive_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def _is_positive_float(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0


def validate_config(cfg):
    """Checks all mandatory fields in config.py. If errors occur, it terminates the operation."""
    errors = []

    # --- string base64 fields ---
    b64_fields = []
    for i in (1, 2, 3):
        b64_fields += [
            f"SALT_B64_{i}", f"NONCE_B64_{i}",
            f"CIPHERTEXT_B64_{i}", f"AUTH_TAG_B64_{i}",
        ]
    for name in b64_fields:
        if not hasattr(cfg, name):
            errors.append(f"  • The variable is missing {name}")
            continue
        val = getattr(cfg, name)
        if not _is_nonempty_str(val):
            errors.append(f"  • {name} empty or not a string")
            continue
        try:
            base64.b64decode(val, validate=True)
        except Exception:
            errors.append(f"  • {name} is not a valid base64")

    # --- logs ---
    for name in ("LOG1", "LOG2", "LOG3"):
        if not hasattr(cfg, name):
            errors.append(f"  • The variable is missing {name}")
        elif not _is_nonempty_str(getattr(cfg, name)):
            errors.append(f"  • {name} empty or not a string")

    # --- KDF ---
    for name in ("ITERATIONS", "DKLEN"):
        if not hasattr(cfg, name):
            errors.append(f"  • The variable is missing {name}")
        elif not _is_positive_int(getattr(cfg, name)):
            errors.append(f"  • {name} must be a positive integer")

    # --- производительность ---
    if not hasattr(cfg, "MAX_WORKERS"):
        errors.append("  • The variable is missing MAX_WORKERS")
    else:
        mw = getattr(cfg, "MAX_WORKERS")
        if not isinstance(mw, int) or isinstance(mw, bool) or mw < 0:
            errors.append("  • MAX_WORKERS must be whole >= 0")

    for name in ("POLL_TIMEOUT", "INTERRUPT_CONFIRM_WINDOW", "WARNING_DURATION"):
        if not hasattr(cfg, name):
            errors.append(f"  • The variable is missing {name}")
        elif not _is_positive_float(getattr(cfg, name)):
            errors.append(f"  • {name} must be a positive number")

    # --- arrays ---
    if not hasattr(cfg, "ARRAYS"):
        errors.append("  • The ARRAYS variable is missing.")
    else:
        arrs = getattr(cfg, "ARRAYS")
        if not isinstance(arrs, list) or len(arrs) == 0:
            errors.append("  • ARRAYS must be a non‑empty list of arrays.")
        else:
            for idx, arr in enumerate(arrs, 1):
                if not isinstance(arr, list):
                    errors.append(f"  • ARRAYS[{idx}] is not a list")
                    continue
                if len(arr) == 0:
                    errors.append(f"  • ARRAYS[{idx}] (arr{idx}) empty — add at least one part")
                    continue
                for j, item in enumerate(arr):
                    if not _is_nonempty_str(item):
                        errors.append(f"  • ARRAYS[{idx}][{j}] an empty string or not a string")

    # --- minimum password length ---
    if not hasattr(cfg, "MIN_PASSWORD_LEN"):
        errors.append("  • The MIN_PASSWORD_LEN variable is missing.")
    elif not _is_positive_int(getattr(cfg, "MIN_PASSWORD_LEN")):
        errors.append("  • MIN_PASSWORD_LEN must be a positive integer.")

    if errors:
        print("❌ Errors have been detected in config.py.:")
        print("\n".join(errors))
        print(f"\n[i] Файл: {CONFIG_PATH}")
        print("[i] Correct the errors and run main.py again.")
        sys.exit(1)


CFG = ensure_config()
validate_config(CFG)
print(f"[i] The configuration is loaded: {CONFIG_PATH}")

# ----- We expand the parameters -----
SALT_B64_1, NONCE_B64_1 = CFG.SALT_B64_1, CFG.NONCE_B64_1
CIPHERTEXT_B64_1, AUTH_TAG_B64_1 = CFG.CIPHERTEXT_B64_1, CFG.AUTH_TAG_B64_1

SALT_B64_2, NONCE_B64_2 = CFG.SALT_B64_2, CFG.NONCE_B64_2
CIPHERTEXT_B64_2, AUTH_TAG_B64_2 = CFG.CIPHERTEXT_B64_2, CFG.AUTH_TAG_B64_2

SALT_B64_3, NONCE_B64_3 = CFG.SALT_B64_3, CFG.NONCE_B64_3
CIPHERTEXT_B64_3, AUTH_TAG_B64_3 = CFG.CIPHERTEXT_B64_3, CFG.AUTH_TAG_B64_3

ITERATIONS = CFG.ITERATIONS
DKLEN      = CFG.DKLEN

LOG1, LOG2, LOG3 = CFG.LOG1, CFG.LOG2, CFG.LOG3

MAX_WORKERS              = CFG.MAX_WORKERS or (os.cpu_count() or 4)
POLL_TIMEOUT             = CFG.POLL_TIMEOUT
INTERRUPT_CONFIRM_WINDOW = CFG.INTERRUPT_CONFIRM_WINDOW
WARNING_DURATION         = CFG.WARNING_DURATION

ARRAYS           = CFG.ARRAYS
MIN_PASSWORD_LEN = CFG.MIN_PASSWORD_LEN

# ---------- Colors ----------
RED    = '\033[91m'
GREEN  = '\033[92m'
GRAY   = '\033[90m'
YELLOW = '\033[93m'
RESET  = '\033[0m'

# ---------- Decoding ----------
def decode_params(salt_b64, nonce_b64, ciphertext_b64, auth_tag_b64):
    try:
        return (base64.b64decode(salt_b64), base64.b64decode(nonce_b64),
                base64.b64decode(ciphertext_b64), base64.b64decode(auth_tag_b64))
    except Exception as e:
        print(f"Base64 decoding error: {e}")
        sys.exit(1)

salt1, nonce1, ct1, tag1 = decode_params(SALT_B64_1, NONCE_B64_1, CIPHERTEXT_B64_1, AUTH_TAG_B64_1)
salt2, nonce2, ct2, tag2 = decode_params(SALT_B64_2, NONCE_B64_2, CIPHERTEXT_B64_2, AUTH_TAG_B64_2)
salt3, nonce3, ct3, tag3 = decode_params(SALT_B64_3, NONCE_B64_3, CIPHERTEXT_B64_3, AUTH_TAG_B64_3)

# ---------- Crypto ----------
def _generate_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, DKLEN)

def try_decrypt(password: str, salt: bytes, nonce: bytes, ciphertext: bytes, auth_tag: bytes):
    key = _generate_key(password, salt)
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext.decode('utf-8', errors='ignore')
    except ValueError:
        return None

# ---------- Worker ----------
_WORKER_CTX = {}

def _init_worker(salt, nonce, ciphertext, auth_tag, iterations, dklen):
    _WORKER_CTX['salt'] = salt
    _WORKER_CTX['nonce'] = nonce
    _WORKER_CTX['ciphertext'] = ciphertext
    _WORKER_CTX['auth_tag'] = auth_tag
    _WORKER_CTX['iterations'] = iterations
    _WORKER_CTX['dklen'] = dklen

def _check_one(password: str):
    ctx = _WORKER_CTX
    key = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), ctx['salt'],
        ctx['iterations'], ctx['dklen']
    )
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=ctx['nonce'])
        plaintext = cipher.decrypt_and_verify(ctx['ciphertext'], ctx['auth_tag'])
        return password, plaintext.decode('utf-8', errors='ignore')
    except ValueError:
        return password, None

# ---------- Logs ----------
def load_checked_passwords(log_filename):
    checked = set()
    if os.path.exists(log_filename):
        try:
            with open(log_filename, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("===") or line.startswith("-"):
                        continue
                    if ": " in line:
                        checked.add(line.split(": ", 1)[1])
        except Exception:
            pass
    return checked

def write_log_header(log_filename):
    if not os.path.exists(log_filename):
        with open(log_filename, "w", encoding="utf-8") as f:
            f.write("=== Log of failed password guessing attempts (PBKDF2-HMAC-SHA256) ===\n")
            f.write(f"Iterations: {ITERATIONS}, DKLEN: {DKLEN}\n")
            f.write("Format: Attempt Number: Password\n")
            f.write("-" * 60 + "\n")

def read_all_passwords_from_log(log_filename):
    passwords = []
    if os.path.exists(log_filename):
        with open(log_filename, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("===") or line.startswith("-"):
                    continue
                if ": " in line:
                    passwords.append(line.split(": ", 1)[1])
    return passwords

def get_last_log_number(log_filename):
    if not os.path.exists(log_filename):
        return 0
    last = 0
    with open(log_filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and ": " in line and not line.startswith("===") and not line.startswith("-"):
                try:
                    num = int(line.split(": ", 1)[0])
                    if num > last:
                        last = num
                except Exception:
                    pass
    return last

def archive_log(log_filename, archive_filename):
    if not os.path.exists(log_filename):
        return
    entries = []
    with open(log_filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("===") or line.startswith("-"):
                continue
            if ": " in line:
                entries.append(line.split(": ", 1)[1])
    if not entries:
        os.remove(log_filename)
        return
    start_num = get_last_log_number(archive_filename) + 1
    with open(archive_filename, "a", encoding="utf-8") as f_arch:
        for i, pwd in enumerate(entries, start=start_num):
            f_arch.write(f"{i}: {pwd}\n")
    os.remove(log_filename)

# ---------- Display ----------
class ProgressDisplay:
    def __init__(self, total, label="Check"):
        self.total = total
        self.done = 0
        self.start_time = time.time()
        self.label = label
        self.last_pwd = ""
        self.status = "Check"
        self.warning = ""
        self.warning_until = 0.0
        self.lines_drawn = 3
        self._started = False

    @staticmethod
    def _fmt_time(seconds):
        if seconds < 1:
            return "<1s"
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            m = int(seconds // 60)
            s = int(seconds % 60)
            return f"{m}m{s:02d}s"
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h{m:02d}m"

    def _render(self):
        if self.warning and time.time() > self.warning_until:
            self.warning = ""

        elapsed = time.time() - self.start_time
        speed = self.done / elapsed if elapsed > 0.2 else 0.0
        remaining = (self.total - self.done) / speed if speed > 0 else 0.0

        pct = (self.done / self.total) if self.total > 0 else 0.0
        bar_width = 30
        filled = int(bar_width * pct)
        bar = '█' * filled + '░' * (bar_width - filled)

        bar_line = (
            f"{self.label} |{bar}| {pct*100:5.1f}% "
            f"({self.done}/{self.total}) "
            f"{speed:6.2f} p/s | ETA {self._fmt_time(remaining)}"
        )

        color = {'Check': GRAY, 'FAIL': RED, 'PASS': GREEN}.get(self.status, '')
        pwd_short = self.last_pwd
        if len(pwd_short) > 70:
            pwd_short = pwd_short[:67] + "..."
        pwd_line = f"{color}[{self.status:5s}]{RESET} {pwd_short}"

        warning_line = f"{YELLOW}{self.warning}{RESET}" if self.warning else ""

        lines = [bar_line, pwd_line, warning_line]

        out = sys.stdout
        if self._started:
            out.write(f"\033[{self.lines_drawn - 1}A\r")
        else:
            out.write("\r")

        for i, ln in enumerate(lines):
            out.write(ln + "\033[K")
            if i < len(lines) - 1:
                out.write("\n\r")

        out.write(f"\033[{len(lines) - 1}A\r")
        out.flush()
        self.lines_drawn = len(lines)
        self._started = True

    def tick_check(self, pwd):
        self.last_pwd = pwd
        self.status = "Check"
        self._render()

    def set_result(self, pwd, status):
        self.last_pwd = pwd
        self.status = status
        self.done += 1
        self._render()

    def set_warning(self, msg, duration=WARNING_DURATION):
        self.warning = msg
        self.warning_until = time.time() + duration
        self._render()

    def finish(self):
        if self._started:
            sys.stdout.write("\n" * self.lines_drawn)
            sys.stdout.flush()
            self._started = False

# ---------- The main hash check ----------
def process_hash(passwords, salt, nonce, ciphertext, auth_tag,
                 log_path, label, extra_passwords=None):
    write_log_header(log_path)

    already = load_checked_passwords(log_path)
    all_pwd = list(passwords)
    if extra_passwords:
        for p in extra_passwords:
            if p not in all_pwd:
                all_pwd.insert(0, p)

    to_check = [p for p in all_pwd if p not in already]
    total = len(to_check)

    print(f"\n=== {label} ===")
    print(f"It has already been verified: {len(already)} | New ones to check: {total}")
    if total == 0:
        print(f"{label}: There’s nothing to check.")
        return None, None

    display = ProgressDisplay(total, label=label)
    display._render()

    log_counter = get_last_log_number(log_path)
    log_file = open(log_path, "a", encoding="utf-8")

    found_password = None
    found_plaintext = None
    interrupted = False
    last_interrupt_time = 0.0

    executor = ProcessPoolExecutor(
        max_workers=MAX_WORKERS,
        initializer=_init_worker,
        initargs=(salt, nonce, ciphertext, auth_tag, ITERATIONS, DKLEN),
    )
    futures = {}
    in_flight = deque()

    try:
        it = iter(to_check)

        for _ in range(MAX_WORKERS):
            try:
                pwd = next(it)
            except StopIteration:
                break
            fut = executor.submit(_check_one, pwd)
            futures[fut] = pwd
            in_flight.append(pwd)

        while futures and not found_password:
            try:
                done, _ = wait(list(futures.keys()),
                               timeout=POLL_TIMEOUT,
                               return_when=FIRST_COMPLETED)
            except KeyboardInterrupt:
                now = time.time()
                if now - last_interrupt_time < INTERRUPT_CONFIRM_WINDOW:
                    interrupted = True
                    break
                last_interrupt_time = now
                display.set_warning(
                    "⚠️  Are you sure you want to stop checking the password? "
                    "Press Ctrl+C again to confirm.",
                    duration=INTERRUPT_CONFIRM_WINDOW,
                )
                continue

            if not done:
                if in_flight:
                    display.tick_check(in_flight[0])
                continue

            for fut in done:
                pwd = futures.pop(fut)
                try:
                    in_flight.remove(pwd)
                except ValueError:
                    pass

                try:
                    _, plain = fut.result()
                except Exception:
                    plain = None

                if plain is not None:
                    display.set_result(pwd, "PASS")
                    found_password = pwd
                    found_plaintext = plain
                    break
                else:
                    log_counter += 1
                    log_file.write(f"{log_counter}: {pwd}\n")
                    log_file.flush()
                    display.set_result(pwd, "FAIL")

                try:
                    new_pwd = next(it)
                    new_fut = executor.submit(_check_one, new_pwd)
                    futures[new_fut] = new_pwd
                    in_flight.append(new_pwd)
                except StopIteration:
                    pass

            if found_password:
                break

    except KeyboardInterrupt:
        interrupted = True
    finally:
        for f in list(futures.keys()):
            f.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        log_file.flush()
        log_file.close()
        display.finish()

    if interrupted:
        print(f"{label}: ⏹  Interrupted by the user (Ctrl+C). The results are saved in {log_path}")
    if found_password:
        print(f"✅ {label}: The password has been FOUND: {found_password}")
        print(f"   Decoded text: {found_plaintext}")
    elif not interrupted:
        print(f"❌ {label}: The password was not found.")

    return found_password, found_plaintext

# ---------- Main block ----------
if __name__ == "__main__":
    if os.name == 'nt':
        os.system('')

    print(f"[i] Workers: {MAX_WORKERS} | Iterations PBKDF2: {ITERATIONS:,}")

    while True:
        ans = input("Should we check all combinations again (overwrite the log) or skip those that have already been checked? "
                    "(y — restart, n — skip): ").strip().lower()
        if ans in ('y', 'n'):
            break
        print("Enter 'y' or 'n'.")

    if ans == 'y':
        archive_log(LOG1, LOG1 + ".old")

    all_passwords = []
    for parts in product(*ARRAYS):
        pwd = "".join(parts)
        if len(pwd) >= MIN_PASSWORD_LEN:
            all_passwords.append(pwd)

    print(f"[i] Combinations have been generated.: {len(all_passwords):,}")
    print("[i] Hint: Ctrl+C — pause/confirm stop "
          "(once — warning, twice in a row — stop).")

    found1, plain1 = process_hash(all_passwords, salt1, nonce1, ct1, tag1,
                                  LOG1, "HASH 1")

    extra_for_2 = None
    extra_for_3 = None
    if found1:
        print(f"\n--- Checking the found password '{found1}' on other hashes ---")
        p2 = try_decrypt(found1, salt2, nonce2, ct2, tag2)
        p3 = try_decrypt(found1, salt3, nonce3, ct3, tag3)
        if p2 is not None:
            print(f"✅ The password is suitable for HASH 2. Decoded: {p2}")
        else:
            print("❌ The password does not match the HASH 2.")
        if p3 is not None:
            print(f"✅ The password is suitable for HASH 1. Decoded: {p3}")
        else:
            print("❌ The password does not match HASH 3.")
        extra_for_2 = [found1]
        extra_for_3 = [found1]

    candidates_2 = read_all_passwords_from_log(LOG1)
    found2, plain2 = process_hash(candidates_2, salt2, nonce2, ct2, tag2,
                                  LOG2, "HASH 2", extra_passwords=extra_for_2)

    extra_3 = list(extra_for_3 or [])
    if found2 and found2 not in extra_3:
        extra_3.append(found2)
    candidates_3 = read_all_passwords_from_log(LOG1)
    found3, plain3 = process_hash(candidates_3, salt3, nonce3, ct3, tag3,
                                  LOG3, "HASH 3", extra_passwords=extra_3 or None)

    print("\n" + "=" * 60)
    print("RESULTS:")
    print(f"HASH 1: {'FOUND' if found1 else 'NOT FOUND'} -> {found1 or '-'}")
    print(f"HASH 2: {'FOUND' if found2 else 'NOT FOUND'} -> {found2 or '-'}")
    print(f"HASH 3: {'FOUND' if found3 else 'NOT FOUND'} -> {found3 or '-'}")
    print("=" * 60)