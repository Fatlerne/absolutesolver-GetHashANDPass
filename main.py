import base64
import hashlib
from Crypto.Cipher import AES
from itertools import product
import os

# === INSERT YOUR DATA HERE ===
SALT_B64 = "zjwPziNdCw/KeJllLzPmRljqfQxNWl8z"  # Your salt (base64)
NONCE_B64 = "U1O6CuxdAEp6AWTA"  # Nonce/IV (12 bytes)
CIPHERTEXT_B64 = "Ln+uvIwB+w+sVtlWLrwm6w=="  # Encrypted data (base64)
AUTH_TAG_B64 = "3Xyql/cHrxBVx0nCFrl7qA=="  # Authentication tag (base64)

ITERATIONS = 2100000  # From the assignment
DKLEN = 32  # AES-256; If it doesn't work, try it 16

LOG_FILENAME = "fail_pass.log"

# Decoding the input data
try:
    salt = base64.b64decode(SALT_B64)
    nonce = base64.b64decode(NONCE_B64)
    ciphertext = base64.b64decode(CIPHERTEXT_B64)
    auth_tag = base64.b64decode(AUTH_TAG_B64)
except Exception as e:
    print(f"Decoding error Base64: {e}")
    exit(1)

if len(nonce) != 12:
    print(f"⚠️ Nonce has a length of {len(nonce)} byte (expected 12). Check the Nonce string.")


def generate_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, DKLEN)


def try_decrypt(password: str) -> str | None:
    key = generate_key(password)
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext.decode('utf-8', errors='ignore')
    except (ValueError, KeyError):
        return None


# === 6 ARRAYS OF SOURCES ===
# REPLACE these lists with the logic of your riddle
arr1 = ["JCJENSON", "0x4A434A454E534F4E"]  # The front door talks too much inside its source code, confessing encrypted data down that road. Under that heading, the first hex alone is yours to take, exactly as shown. Other hex under other names? Dead archive bones.
arr2 = ["FEBXBRR", "SOLVERS", "copper-9", "0x636F707065722D39"]  # Where every honest route crawls off to die, first builder’s comment names a cipher key. Don’t be shy. Later comments are rotated, old builds, expired and done. You want the first one. Only the first one.
arr3 = ["63796e2f", "cyn/", "copper-9", "0x636F707065722D39"]  # The polite ghost file mapping who built this maze hides one last copper joke in a hex-encoded phrase. Steal the whole token, prefix and all. Drop any part of it and you’ll hit a wall.
arr4 = ["solver", "copper", "listen"]  # Six letters the cultists trade for the listening pit, lowercase, always lowercase, every last bit.
arr5 = ["assetssolver-core", "a9f3b7c2d1e47a2d"]  # Sixteen characters name the hole you’re standing in. No slashes, no mercy. Just the name of this bin.
arr6 = ["3047", "3054", "2026", "0041", "0047", "6094", "6108", "4052", "0082", "0094"]  # Four digits the front door buries twice in its oldest closing seal. Look once. Look twice.

arrays = [arr1, arr2, arr3, arr4, arr5, arr6]

# --- LOGIC OF WORKING WITH LOG ---

# A set for storing already verified passwords (fast O(1) search)
checked_passwords = set()

# If the log exists, read it
if os.path.exists(LOG_FILENAME):
    print(f"📂 File detected '{LOG_FILENAME}'. Reading the history of attempts...")
    try:
        with open(LOG_FILENAME, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip header lines and empty lines
                if line.startswith("=== Лог") or line.startswith("-") or line == "":
                    continue
                # Log line format: "number: password""
                # We only need the part after the colon and the space
                if ": " in line:
                    pwd = line.split(": ", 1)[1]
                    checked_passwords.add(pwd)
                else:
                    # Fallback if the format is strange: consider the entire string as a password
                    # (it's better to avoid this format, but for compatibility)
                    if len(line) > 2:
                        checked_passwords.add(line)
        print(f"✅ Loaded {len(checked_passwords)} previously checked passwords.")
    except Exception as e:
        print(f"⚠️ Failed to read the log (possibly corrupted): {e}. Let's start from scratch.")
else:
    print(f"📝The file '{LOG_FILENAME}' was not found. We will create a new one if the first attempt fails.")

total_combinations = 1
for arr in arrays:
    total_combinations *= len(arr)

print(f"🔍 Total number of potential combinations from arrays: {total_combinations:,}")
print(f"The following will be skipped (already in the log): ~{len(checked_passwords)} (if they match the current generation)")
print("We begin the search...\n")

found = False
attempt_count = 0
new_failures_count = 0

# Open the file in APPEND mode ("a") to avoid erasing the history
# But we need to be careful with the header if the file is new.
is_new_log = not os.path.exists(LOG_FILENAME)

with open(LOG_FILENAME, "a", encoding="utf-8") as log_file:
    # If the file is new, write the header
    if is_new_log:
        log_file.write("=== Log of failed password attempts (PBKDF2-HMAC-SHA256)===\n")
        log_file.write(f"Iterations: {ITERATIONS}, DKLEN: {DKLEN}\n")
        log_file.write("Line format: Attempt number: Password\n")
        log_file.write("-" * 60 + "\n")

    # To avoid doing a flush on each line (which is slow), we will buffer
    # However, for safety reasons, you can flush periodically during a crash.

    for parts in product(*arrays):
        password = "".join(parts)

        if len(password) < 6:
            continue

        # MAIN CHECK: Was there already a password like this?
        if password in checked_passwords:
            continue  # We've already tried this.

        attempt_count += 1

        # Progress to the console
        if attempt_count % 50 == 0:
            print(f"New attempts checked: {attempt_count:,} ...")

        result = try_decrypt(password)

        if result is not None:
            print("\n" + "=" * 50)
            print("✅ PASSWORD FOUND!")
            print(f"password: {password}")
            print("-" * 50)
            print("The decrypted text:")
            print(result)
            print("=" * 50)
            found = True
            break
        else:
            # This is a new failed attempt.
            new_failures_count += 1
            log_entry = f"{attempt_count}: {password}\n"
            log_file.write(log_entry)

            # We add it to memory so that it doesn't get duplicated during this run
            checked_passwords.add(password)

            # Periodic disk buffer flush (every 100 records)
            if new_failures_count % 100 == 0:
                log_file.flush()

if not found:
    print("\n❌ No new combination worked.")
    print(f"Added to the log of new failed attempts: {new_failures_count}")
    print(f"Total number of known failed passwords '{LOG_FILENAME}': {len(checked_passwords)}")
    print("\n💡 Tip: If you have changed the arrays (added new words), but the password is still not found,")
    print("   You may want to temporarily rename fail_pass.log to fail_pass.log.old to reset the filter")
    print("   since new combinations may have the same meaning as old ones, but the generation logic may have changed.")
else:
    print(f"\n✅ The task is solved! {new_failures_count} new failed attempts have been added to the log.")
