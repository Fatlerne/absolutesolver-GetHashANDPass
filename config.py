# ============================================================
#  PASSWORD SELECTION CONFIG
#  Change the hashes, logs, and arrays of password parts here.
#  Main.py reads this file and does not require any modifications.
# ============================================================

# ---------- HASH 1 ----------
SALT_B64_1       = "zjwPziNdCw/KeJllLzPmRljqfQxNWl8z"
NONCE_B64_1      = "U1O6CuxdAEp6AWTA"
CIPHERTEXT_B64_1 = "Ln+uvIwB+w+sVtlWLrwm6w=="
AUTH_TAG_B64_1   = "3Xyql/cHrxBVx0nCFrl7qA=="

# ---------- HASH 2 ----------
SALT_B64_2       = "6gV965IdM2b7zzmDy2gXcpp1DgawiXBq"
NONCE_B64_2      = "p7bkD7c2zDnQivbU"
CIPHERTEXT_B64_2 = "nSvFpXe1F6U7IwVJlEDR6A=="
AUTH_TAG_B64_2   = "0bHBGmj1mZH2hm/OEjVnsQ=="

# ---------- HASH 3 ----------
SALT_B64_3       = "QkPTT/H3zL3SyLJUVlpO7Pt70TJn8teS"
NONCE_B64_3      = "L1nItTFIU/gANvN3"
CIPHERTEXT_B64_3 = "MsDJIehDfbw8s2SQlARMKQ=="
AUTH_TAG_B64_3   = "ypc32PBsQyVO6i59052+NQ=="

# ---------- PARAMETERS KDF ----------
ITERATIONS = 2_100_000
DKLEN      = 32

# ---------- LOGS ----------
LOG1 = "fail_pass.log"
LOG2 = "fail_pass2.log"
LOG3 = "fail_pass3.log"

# ---------- EFFICIENCY ----------
MAX_WORKERS              = 0      # 0 = auto (os.cpu_count())
POLL_TIMEOUT             = 0.05   # The period for surveying completed tasks, sec.
INTERRUPT_CONFIRM_WINDOW = 5.0    # confirmation window Ctrl+C, sec
WARNING_DURATION         = 5.0    # How long to display the warning, sec.

# ============================================================
#  PASSWORD PARTS ARRAYS
#  The final password = concatenation of one part from each array
#  (Cartesian product). Exactly 6 arrays — as in the original code.
# ============================================================
arr1 = ["JCJENSON", "0x4A434A454E534F4E"]

arr2 = ["FEBXBRR", "SOLVERS", "SOLVER", "0x534F4C564552"]

arr3 = ["copper-9", "cyn/", "0x636F707065722D39"]

arr4 = ["solver", "copper", "listen", "glados"]

arr5 = [
    "assetssolver-core", "1764476138510png", "a9f3b7c2d1e47A2D", "INTERCEPTSTATION",
    "7368a0eb81b2584bc4d8", "c94f4646a9f3b7c2", "a9f3b7c2d1e4final", "U1O6CuxdAEp6AWTA",
    "p7bkD7c2zDnQivbU", "L1nItTFIUgANvN3", "absolutesolver.com",
    "6162736f6c757465736f6c7665722e636f6d",
    "0x6162736f6c757465736f6c7665722e636f6d", "6162736f6c757465736f6c766572",
    "0x6162736f6c757465736f6c766572", "a9f3b7c2d1e4GLSB", "5c4f803c62e07754",
]

arr6 = ["3047", "3054", "2026", "0041", "0047", "7368", "3742", "3044", "3045", "3002"]

# A list of arrays in the order of concatenation.
# Change the order/content, but keep the list made up of these arrays.
ARRAYS = [arr1, arr2, arr3, arr4, arr5, arr6]

# The minimum length of the final password
MIN_PASSWORD_LEN = 6