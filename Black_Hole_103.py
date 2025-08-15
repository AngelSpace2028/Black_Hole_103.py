import os
import sys
import math
import struct
import array
import random
import heapq
import binascii
import logging
import paq  # Python binding for PAQ9a (pip install paq)
import hashlib
from typing import List, Dict, Tuple, Optional

# === Configure Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# === Constants ===
PROGNAME = "PAQJP_6_Smart"
HUFFMAN_THRESHOLD = 1024  # Bytes threshold for Huffman vs. paq compression
PI_DIGITS_FILE = "pi_digits.txt"
PRIMES = [p for p in range(2, 256) if all(p % d != 0 for d in range(2, int(p**0.5)+1))]
MEM = 1 << 15  # 32,768

# === Dictionary file list ===
DICTIONARY_FILES = [
    "eng_news_2005_1M-sentences.txt", "eng_news_2005_1M-words.txt",
    "eng_news_2005_1M-sources.txt", "eng_news_2005_1M-co_n.txt",
    "eng_news_2005_1M-co_s.txt", "eng_news_2005_1M-inv_so.txt",
    "eng_news_2005_1M-meta.txt", "Dictionary.txt",
    "the-complete-reference-html-css-fifth-edition.txt",
    "words.txt.paq", "lines.txt.paq", "sentence.txt.paq"
]

# === Pi Digits Functions ===
def save_pi_digits(digits: List[int], filename: str = PI_DIGITS_FILE) -> bool:
    try:
        with open(filename, 'w') as f:
            f.write(','.join(str(d) for d in digits))
        logging.info(f"Successfully saved {len(digits)} base-10 pi digits to {filename}")
        return True
    except Exception as e:
        logging.error(f"Failed to save base-10 pi digits to {filename}: {e}")
        return False

def load_pi_digits(filename: str = PI_DIGITS_FILE, expected_count: int = 3) -> Optional[List[int]]:
    try:
        if not os.path.isfile(filename):
            logging.warning(f"Base-10 pi digits file {filename} does not exist")
            return None
        with open(filename, 'r') as f:
            data = f.read().strip()
            if not data:
                logging.warning(f"Base-10 pi digits file {filename} is empty")
                return None
            digits = []
            for x in data.split(','):
                if not x.isdigit():
                    logging.warning(f"Invalid integer in {filename}: {x}")
                    return None
                d = int(x)
                if not (0 <= d <= 255):
                    logging.warning(f"Digit out of range in {filename}: {d}")
                    return None
                digits.append(d)
            if len(digits) != expected_count:
                logging.warning(f"Loaded {len(digits)} digits, expected {expected_count}")
                return None
            logging.info(f"Successfully loaded {len(digits)} base-10 pi digits from {filename}")
            return digits
    except Exception as e:
        logging.error(f"Failed to load base-10 pi digits from {filename}: {e}")
        return None

def generate_pi_digits(num_digits: int = 3, filename: str = PI_DIGITS_FILE) -> List[int]:
    loaded_digits = load_pi_digits(filename, num_digits)
    if loaded_digits is not None:
        return loaded_digits
    try:
        from mpmath import mp
        mp.dps = num_digits
        pi_digits = [int(d) for d in mp.pi.digits(10)[0]]
        if len(pi_digits) != num_digits:
            logging.error(f"Generated {len(pi_digits)} digits, expected {num_digits}")
            raise ValueError("Incorrect number of pi digits generated")
        if not all(0 <= d <= 9 for d in pi_digits):
            logging.error("Generated pi digits contain invalid values")
            raise ValueError("Invalid pi digits generated")
        mapped_digits = [(d * 255 // 9) % 256 for d in pi_digits]
        save_pi_digits(mapped_digits, filename)
        return mapped_digits
    except Exception as e:
        logging.error(f"Failed to generate base-10 pi digits: {e}")
        fallback_digits = [3, 1, 4]
        mapped_fallback = [(d * 255 // 9) % 256 for d in fallback_digits[:num_digits]]
        logging.warning(f"Using {len(mapped_fallback)} fallback base-10 digits")
        save_pi_digits(mapped_fallback, filename)
        return mapped_fallback

PI_DIGITS = generate_pi_digits(3)

# === Helper Classes and Functions from PAQJP_6 ===
class Filetype(Enum):
    DEFAULT = 0
    JPEG = 1
    TEXT = 3

class Node:
    def __init__(self, left=None, right=None, symbol=None):
        self.left = left
        self.right = right
        self.symbol = symbol

    def is_leaf(self):
        return self.left is None and self.right is None

def transform_with_prime_xor_every_3_bytes(data, repeat=100):
    transformed = bytearray(data)
    for prime in PRIMES:
        xor_val = prime if prime == 2 else max(1, math.ceil(prime * 4096 / 28672))
        for _ in range(repeat):
            for i in range(0, len(transformed), 3):
                transformed[i] ^= xor_val
    return bytes(transformed)

def transform_with_pattern_chunk(data, chunk_size=4):
    transformed = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        transformed.extend([b ^ 0xFF for b in chunk])
    return bytes(transformed)

def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def find_nearest_prime_around(n):
    offset = 0
    while True:
        if is_prime(n - offset):
            return n - offset
        if is_prime(n + offset):
            return n + offset
        offset += 1

# === Smart Compressor (with dictionary functionality) ===
class SmartCompressor:
    def __init__(self):
        self.dictionaries = self.load_dictionaries()

    def load_dictionaries(self):
        """Load dictionary files for hash searching."""
        data = []
        for filename in DICTIONARY_FILES:
            if os.path.exists(filename):
                try:
                    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                        data.append(f.read())
                    logging.info(f"Loaded dictionary file: {filename}")
                except Exception as e:
                    logging.warning(f"Could not read {filename}: {e}")
            else:
                logging.warning(f"Missing dictionary file: {filename}")
        return data

    def compute_sha256(self, data):
        """Compute SHA-256 hash of data in hexadecimal."""
        return hashlib.sha256(data).hexdigest()

    def compute_sha256_binary(self, data):
        """Compute SHA-256 hash of data in binary (32 bytes)."""
        return hashlib.sha256(data).digest()

    def find_hash_in_dictionaries(self, hash_hex):
        """Search for the hash in dictionary files."""
        for filename in DICTIONARY_FILES:
            if not os.path.exists(filename):
                continue
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if hash_hex in line:
                            logging.info(f"Hash {hash_hex[:16]}... found in {filename}")
                            return filename
            except Exception as e:
                logging.warning(f"Error searching {filename}: {e}")
        return None

    def generate_8byte_sha(self, data):
        """Generate first 8 bytes of SHA-256 hash for a file."""
        try:
            full_hash = hashlib.sha256(data).digest()
            return full_hash[:8]
        except Exception as e:
            logging.error(f"Failed to generate SHA: {e}")
            return None

    def paq_compress(self, data):
        """Compress data using PAQ9a (lossless)."""
        if not data:
            logging.warning("paq_compress: Empty input data, returning empty bytes")
            return b''
        try:
            compressed = paq.compress(data)
            logging.info("PAQ9a compression complete.")
            return compressed
        except Exception as e:
            logging.error(f"PAQ9a compression failed: {e}")
            return None

    def paq_decompress(self, data):
        """Decompress data using PAQ9a (lossless)."""
        if not data:
            logging.warning("paq_decompress: Empty input data, returning empty bytes")
            return b''
        try:
            decompressed = paq.decompress(data)
            logging.info("PAQ9a decompression complete.")
            return decompressed
        except Exception as e:
            logging.error(f"PAQ9a decompression failed: {e}")
            return None

    def reversible_transform(self, data):
        """Apply reversible XOR transform with 0xAA."""
        logging.info("Applying XOR transform (0xAA)...")
        transformed = bytes(b ^ 0xAA for b in data)
        logging.info("XOR transform complete.")
        return transformed

    def reverse_reversible_transform(self, data):
        """Reverse the XOR transform (symmetric)."""
        logging.info("Reversing XOR transform (0xAA)...")
        transformed = self.reversible_transform(data)  # XOR with 0xAA is symmetric
        logging.info("XOR transform reversed.")
        return transformed

    def compress(self, input_data, input_file):
        """Compress data with dictionary-based hash verification."""
        if not input_data:
            logging.warning("Empty input data, returning minimal output")
            return bytes([0])

        original_hash = self.compute_sha256(input_data)
        logging.info(f"SHA-256 of input: {original_hash[:16]}...")

        # Check if hash exists in dictionaries
        found = self.find_hash_in_dictionaries(original_hash)
        if found:
            logging.info(f"Hash found in dictionary: {found}")
        else:
            logging.info("Hash not found in any dictionary. Proceeding with lossless compression.")

        # Special case for .paq dictionary files
        if input_file.endswith(".paq") and any(x in input_file for x in ["words", "lines", "sentence"]):
            sha = self.generate_8byte_sha(input_data)
            if sha and len(input_data) > 8:
                logging.info(f"SHA-8 for .paq file: {sha.hex()}")
                return sha
            logging.info("Original file smaller than SHA hash, skipping compression.")
            return None

        # Normal compression flow (lossless)
        transformed = self.reversible_transform(input_data)
        compressed = self.paq_compress(transformed)
        if compressed is None:
            logging.error("Compression failed.")
            return None

        if len(compressed) < len(input_data):
            output = self.compute_sha256_binary(input_data) + compressed
            logging.info(f"Smart compression successful. Original size: {len(input_data)} bytes, Compressed size: {len(compressed)} bytes")
            return output
        else:
            logging.info("Compression not efficient. Returning None.")
            return None

    def decompress(self, input_data):
        """Decompress data with hash verification."""
        if len(input_data) < 32:
            logging.error("Input data too short for Smart Compressor.")
            return None

        stored_hash = input_data[:32]
        compressed_data = input_data[32:]

        decompressed = self.paq_decompress(compressed_data)
        if decompressed is None:
            return None

        original = self.reverse_reversible_transform(decompressed)
        computed_hash = self.compute_sha256_binary(original)
        if computed_hash == stored_hash:
            logging.info("Hash verification successful.")
            return original
        else:
            logging.error("Hash verification failed! Data may be corrupted.")
            return None

# === PAQJP Compressor (without datetime) ===
class PAQJPCompressor:
    def __init__(self):
        self.PI_DIGITS = PI_DIGITS
        self.PRIMES = PRIMES
        self.seed_tables = self.generate_seed_tables()
        self.SQUARE_OF_ROOT = 2
        self.ADD_NUMBERS = 1
        self.MULTIPLY = 3

    def generate_seed_tables(self, num_tables=126, table_size=256, min_val=5, max_val=255, seed=42):
        random.seed(seed)
        tables = []
        for _ in range(num_tables):
            table = [random.randint(min_val, max_val) for _ in range(table_size)]
            tables.append(table)
        return tables

    def get_seed(self, table_idx: int, value: int) -> int:
        if 0 <= table_idx < len(self.seed_tables):
            return self.seed_tables[table_idx][value % len(self.seed_tables[table_idx])]
        return 0

    def calculate_frequencies(self, binary_str):
        if not binary_str:
            logging.warning("Empty binary string, returning empty frequencies")
            return {}
        frequencies = {}
        for bit in binary_str:
            frequencies[bit] = frequencies.get(bit, 0) + 1
        return frequencies

    def build_huffman_tree(self, frequencies):
        if not frequencies:
            logging.warning("No frequencies provided, returning None for Huffman tree")
            return None
        heap = [(freq, Node(symbol=symbol)) for symbol, freq in frequencies.items()]
        heapq.heapify(heap)
        while len(heap) > 1:
            freq1, node1 = heapq.heappop(heap)
            freq2, node2 = heapq.heappop(heap)
            new_node = Node(left=node1, right=node2)
            heapq.heappush(heap, (freq1 + freq2, new_node))
        return heap[0][1]

    def generate_huffman_codes(self, root, current_code="", codes={}):
        if root is None:
            logging.warning("Huffman tree is None, returning empty codes")
            return {}
        if root.is_leaf():
            codes[root.symbol] = current_code or "0"
            return codes
        if root.left:
            self.generate_huffman_codes(root.left, current_code + "0", codes)
        if root.right:
            self.generate_huffman_codes(root.right, current_code + "1", codes)
        return codes

    def compress_data_huffman(self, binary_str):
        if not binary_str:
            logging.warning("Empty binary string, returning empty compressed string")
            return ""
        frequencies = self.calculate_frequencies(binary_str)
        huffman_tree = self.build_huffman_tree(frequencies)
        if huffman_tree is None:
            return ""
        huffman_codes = self.generate_huffman_codes(huffman_tree)
        if '0' not in huffman_codes:
            huffman_codes['0'] = '0'
        if '1' not in huffman_codes:
            huffman_codes['1'] = '1'
        compressed_str = ''.join(huffman_codes[bit] for bit in binary_str)
        return compressed_str

    def decompress_data_huffman(self, compressed_str):
        if not compressed_str:
            logging.warning("Empty compressed string, returning empty decompressed string")
            return ""
        frequencies = self.calculate_frequencies(compressed_str)
        huffman_tree = self.build_huffman_tree(frequencies)
        if huffman_tree is None:
            return ""
        huffman_codes = self.generate_huffman_codes(huffman_tree)
        reversed_codes = {code: symbol for symbol, code in huffman_codes.items()}
        decompressed_str = ""
        current_code = ""
        for bit in compressed_str:
            current_code += bit
            if current_code in reversed_codes:
                decompressed_str += reversed_codes[current_code]
                current_code = ""
        return decompressed_str

    def paq_compress(self, data):
        if not data:
            logging.warning("paq_compress: Empty input data, returning empty bytes")
            return b''
        try:
            return paq.compress(data)
        except Exception as e:
            logging.error(f"PAQ9a compression failed: {e}")
            return None

    def paq_decompress(self, data):
        if not data:
            logging.warning("paq_decompress: Empty input data, returning empty bytes")
            return b''
        try:
            return paq.decompress(data)
        except Exception as e:
            logging.error(f"PAQ9a decompression failed: {e}")
            return None

    def transform_01(self, data, repeat=100):
        if not data:
            logging.warning("transform_01: Empty input data, returning empty bytes")
            return b''
        return transform_with_prime_xor_every_3_bytes(data, repeat=repeat)

    def reverse_transform_01(self, data, repeat=100):
        if not data:
            logging.warning("reverse_transform_01: Empty input data, returning empty bytes")
            return b''
        return self.transform_01(data, repeat=repeat)

    def transform_03(self, data):
        if not data:
            logging.warning("transform_03: Empty input data, returning empty bytes")
            return b''
        return transform_with_pattern_chunk(data)

    def reverse_transform_03(self, data):
        if not data:
            logging.warning("reverse_transform_03: Empty input data, returning empty bytes")
            return b''
        return self.transform_03(data)

    def transform_04(self, data, repeat=100):
        if not data:
            logging.warning("transform_04: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] - (i % 256)) % 256
        return bytes(transformed)

    def reverse_transform_04(self, data, repeat=100):
        if not data:
            logging.warning("reverse_transform_04: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] + (i % 256)) % 256
        return bytes(transformed)

    def transform_05(self, data, shift=3):
        if not data:
            logging.warning("transform_05: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = ((transformed[i] << shift) | (transformed[i] >> (8 - shift))) & 0xFF
        return bytes(transformed)

    def reverse_transform_05(self, data, shift=3):
        if not data:
            logging.warning("reverse_transform_05: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = ((transformed[i] >> shift) | (transformed[i] << (8 - shift))) & 0xFF
        return bytes(transformed)

    def transform_06(self, data, seed=42):
        if not data:
            logging.warning("transform_06: Empty input data, returning empty bytes")
            return b''
        random.seed(seed)
        substitution = list(range(256))
        random.shuffle(substitution)
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = substitution[transformed[i]]
        return bytes(transformed)

    def reverse_transform_06(self, data, seed=42):
        if not data:
            logging.warning("reverse_transform_06: Empty input data, returning empty bytes")
            return b''
        random.seed(seed)
        substitution = list(range(256))
        random.shuffle(substitution)
        reverse_substitution = [0] * 256
        for i, v in enumerate(substitution):
            reverse_substitution[v] = i
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = reverse_substitution[transformed[i]]
        return bytes(transformed)

    def transform_07(self, data, repeat=100):
        if not data:
            logging.warning("transform_07: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_07: Using {cycles} cycles for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_byte = len(data) % 256
        for i in range(len(transformed)):
            transformed[i] ^= size_byte

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        return bytes(transformed)

    def reverse_transform_07(self, data, repeat=100):
        if not data:
            logging.warning("reverse_transform_07: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_07: Using {cycles} cycles for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        size_byte = len(data) % 256
        for i in range(len(transformed)):
            transformed[i] ^= size_byte

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_08(self, data, repeat=100):
        if not data:
            logging.warning("transform_08: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_08: Using {cycles} cycles for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_prime = find_nearest_prime_around(len(data) % 256)
        for i in range(len(transformed)):
            transformed[i] ^= size_prime

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        return bytes(transformed)

    def reverse_transform_08(self, data, repeat=100):
        if not data:
            logging.warning("reverse_transform_08: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_08: Using {cycles} cycles for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        size_prime = find_nearest_prime_around(len(data) % 256)
        for i in range(len(transformed)):
            transformed[i] ^= size_prime

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_09(self, data, repeat=100):
        if not data:
            logging.warning("transform_09: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_09: Using {cycles} cycles with {repeat} repeats for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_prime = find_nearest_prime_around(len(data) % 256)
        seed_idx = len(data) % len(self.seed_tables)
        seed_value = self.get_seed(seed_idx, len(data))
        for i in range(len(transformed)):
            transformed[i] ^= size_prime ^ seed_value

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit ^ (i % 256)

        return bytes(transformed)

    def reverse_transform_09(self, data, repeat=100):
        if not data:
            logging.warning("reverse_transform_09: Empty input data, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_09: Using {cycles} cycles with {repeat} repeats for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit ^ (i % 256)

        size_prime = find_nearest_prime_around(len(data) % 256)
        seed_idx = len(data) % len(self.seed_tables)
        seed_value = self.get_seed(seed_idx, len(data))
        for i in range(len(transformed)):
            transformed[i] ^= size_prime ^ seed_value

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_10(self, data, repeat=100):
        if not data:
            logging.warning("transform_10: Empty input data, returning empty bytes with n=0")
            return bytes([0])
        transformed = bytearray(data)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_10: Using {cycles} cycles with {repeat} repeats for {len(data)} bytes")

        count = 0
        for i in range(len(data) - 1):
            if data[i] == 0x58 and data[i + 1] == 0x31:
                count += 1
        logging.info(f"transform_10: Found {count} 'X1' sequences")

        n = (((count * self.SQUARE_OF_ROOT) + self.ADD_NUMBERS) // 3) * self.MULTIPLY
        n = n % 256
        logging.info(f"transform_10: Computed n = {n}")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                transformed[i] ^= n

        return bytes([n]) + bytes(transformed)

    def reverse_transform_10(self, data, repeat=100):
        if len(data) < 1:
            logging.warning("reverse_transform_10: Data too short, returning empty bytes")
            return b''
        n = data[0]
        transformed = bytearray(data[1:])
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_10: Using {cycles} cycles with {repeat} repeats for {len(data)} bytes, n = {n}")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                transformed[i] ^= n

        return bytes(transformed)

    def transform_11(self, data, repeat=100):
        if not data:
            logging.warning("transform_11: Empty input data, returning y=0 with no data")
            return struct.pack('B', 0)
        y_values = range(1, 256)
        best_result = None
        best_y = None
        best_size = float('inf')
        zero_count = sum(1 for b in data if b == 0)
        logging.info(f"transform_11: Testing {len(y_values)} y values for {len(data)} bytes with {repeat} repeats, {zero_count} zero bytes")
        for y in y_values:
            transformed = bytearray(data)
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] = (transformed[i] + y + 1) % 256
            try:
                compressed = self.paq_compress(transformed)
                if compressed is None:
                    logging.warning(f"transform_11: Compression with y={y} returned None")
                    continue
                if len(compressed) < best_size:
                    best_result = compressed
                    best_y = y
                    best_size = len(compressed)
            except Exception as e:
                logging.warning(f"transform_11: Compression with y={y} failed: {e}")
                continue
        if best_result is None:
            logging.error("transform_11: All compression attempts failed, returning original data with y=0")
            return struct.pack('B', 0) + data
        logging.info(f"transform_11: Selected y={best_y} with compressed size {best_size}")
        return struct.pack('B', best_y) + best_result

    def reverse_transform_11(self, data, repeat=100):
        if len(data) < 1:
            logging.warning("reverse_transform_11: Data too short to contain y, returning empty bytes")
            return b''
        y = struct.unpack('B', data[:1])[0]
        compressed_data = data[1:]
        if not compressed_data:
            logging.warning("reverse_transform_11: No compressed data after y, returning empty bytes")
            return b''
        try:
            decompressed = self.paq_decompress(compressed_data)
            if not decompressed:
                logging.warning("reverse_transform_11: Decompression returned empty data")
                return b''
        except Exception as e:
            logging.error(f"reverse_transform_11: Decompression failed: {e}")
            return b''
        transformed = bytearray(decompressed)
        zero_count = sum(1 for b in transformed if b == 0)
        logging.info(f"reverse_transform_11: Processing {len(transformed)} bytes with y={y}, {zero_count} zero bytes, {repeat} repeats")
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] - y - 1) % 256
        zero_count_after = sum(1 for b in transformed if b == 0)
        logging.info(f"reverse_transform_11: Restored data, {zero_count_after} zero bytes after transformation")
        return bytes(transformed)

    def generate_transform_method(self, marker):
        def transform(data, repeat=1000):
            if not data:
                logging.warning(f"transform_{marker}: Empty input data, returning empty bytes")
                return b''
            transformed = bytearray(data)
            data_size = len(data)
            scale_factor = max(2000, min(256000, data_size))
            size_mod = (data_size % scale_factor) % 256
            logging.info(f"transform_{marker}: Using size_mod={size_mod} for {data_size} bytes, repeat={repeat}")
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] ^= (size_mod + (i % 256)) % 256
            return bytes(transformed)

        def reverse_transform(data, repeat=1000):
            if not data:
                logging.warning(f"reverse_transform_{marker}: Empty input data, returning empty bytes")
                return b''
            transformed = bytearray(data)
            data_size = len(data)
            scale_factor = max(2000, min(256000, data_size))
            size_mod = (data_size % scale_factor) % 256
            logging.info(f"reverse_transform_{marker}: Using size_mod={size_mod} for {data_size} bytes, repeat={repeat}")
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] ^= (size_mod + (i % 256)) % 256
            return bytes(transformed)
        return transform, reverse_transform

    def compress_with_best_method(self, data, filetype, input_filename, mode="slow"):
        if not data:
            logging.warning("compress_with_best_method: Empty input data, returning minimal marker")
            return bytes([0])

        fast_transformations = [
            (1, self.transform_04),
            (2, self.transform_01),
            (3, self.transform_03),
            (5, self.transform_05),
            (6, self.transform_06),
            (7, self.transform_07),
            (8, self.transform_08),
            (9, self.transform_09),
        ]
        slow_transformations = fast_transformations + [
            (10, self.transform_10),
            (11, self.transform_11),
        ] + [(i, self.generate_transform_method(i)[0]) for i in range(12, 256)]

        transformations = slow_transformations if mode == "slow" else fast_transformations

        if filetype in [Filetype.JPEG, Filetype.TEXT]:
            prioritized = [(7, self.transform_07), (8, self.transform_08), (9, self.transform_09)]
            if mode == "slow":
                prioritized += [(10, self.transform_10), (11, self.transform_11)] + \
                              [(i, self.generate_transform_method(i)[0]) for i in range(12, 256)]
            transformations = prioritized + [t for t in transformations if t[0] not in [7, 8, 9, 10, 11] + list(range(12, 256))]

        methods = [('paq', self.paq_compress)]
        best_compressed = None
        best_size = float('inf')
        best_marker = None
        best_method = None

        for marker, transform in transformations:
            transformed = transform(data)
            for method_name, compress_func in methods:
                try:
                    compressed = compress_func(transformed)
                    if compressed is None:
                        continue
                    size = len(compressed)
                    if size < best_size:
                        best_size = size
                        best_compressed = compressed
                        best_marker = marker
                        best_method = method_name
                except Exception as e:
                    logging.warning(f"Compression method {method_name} with transform {marker} failed: {e}")
                    continue

        if len(data) < HUFFMAN_THRESHOLD:
            binary_str = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8)
            compressed_huffman = self.compress_data_huffman(binary_str)
            compressed_bytes = int(compressed_huffman, 2).to_bytes((len(compressed_huffman) + 7) // 8, 'big') if compressed_huffman else b''
            if compressed_bytes and len(compressed_bytes) < best_size:
                best_size = len(compressed_bytes)
                best_compressed = compressed_bytes
                best_marker = 4
                best_method = 'huffman'

        if best_compressed is None:
            logging.error("All compression methods failed, returning original data with marker 0")
            return bytes([0]) + data

        logging.info(f"Best compression method: {best_method}, Marker: {best_marker} for {filetype.name} in {mode} mode")
        return bytes([best_marker]) + best_compressed

    def decompress_with_best_method(self, data):
        if len(data) < 1:
            logging.warning("decompress_with_best_method: Insufficient data, returning empty bytes")
            return b'', None

        method_marker = data[0]
        compressed_data = data[1:]

        reverse_transforms = {
            1: self.reverse_transform_04,
            2: self.reverse_transform_01,
            3: self.reverse_transform_03,
            5: self.reverse_transform_05,
            6: self.reverse_transform_06,
            7: self.reverse_transform_07,
            8: self.reverse_transform_08,
            9: self.reverse_transform_09,
            10: self.reverse_transform_10,
            11: self.reverse_transform_11,
        }
        reverse_transforms.update({i: self.generate_transform_method(i)[1] for i in range(12, 256)})

        if method_marker == 4:
            binary_str = bin(int(binascii.hexlify(compressed_data), 16))[2:].zfill(len(compressed_data) * 8)
            decompressed_binary = self.decompress_data_huffman(binary_str)
            if not decompressed_binary:
                logging.warning("Huffman decompression returned empty string")
                return b'', None
            try:
                num_bytes = (len(decompressed_binary) + 7) // 8
                hex_str = "%0*x" % (num_bytes * 2, int(decompressed_binary, 2))
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                return binascii.unhexlify(hex_str), None
            except Exception as e:
                logging.error(f"Error converting decompressed Huffman data: {e}")
                return b'', None

        if method_marker not in reverse_transforms:
            logging.error(f"Unknown compression method marker: {method_marker}")
            return b'', None

        try:
            decompressed = self.paq_decompress(compressed_data)
            if not decompressed:
                logging.warning("PAQ decompression returned empty data")
                return b'', None
            result = reverse_transforms[method_marker](decompressed)
            zero_count = sum(1 for b in result if b == 0)
            logging.info(f"Decompressed with marker {method_marker}, {zero_count} zero bytes in result")
            return result, method_marker
        except Exception as e:
            logging.error(f"PAQ decompression failed: {e}")
            return b'', None

# === Combined Compressor ===
class CombinedCompressor:
    def __init__(self):
        self.smart_compressor = SmartCompressor()
        self.paqjp_compressor = PAQJPCompressor()

    def compress(self, input_file, output_file, mode="slow"):
        """Compress file using the best method (Smart Compressor or PAQJP_6)."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found.")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}.")
            return
        if os.path.getsize(input_file) == 0:
            logging.warning(f"Input file '{input_file}' is empty, writing empty output")
            with open(output_file, 'wb') as f_out:
                f_out.write(bytes([0]))
            return

        with open(input_file, "rb") as f:
            input_data = f.read()

        # Try Smart Compressor (marker 00)
        smart_compressed = self.smart_compressor.compress(input_data, input_file)
        smart_output = bytes([0x00]) + smart_compressed if smart_compressed else b''

        # Try PAQJP_6 Compressor (marker 01)
        filetype = detect_filetype(input_file)
        paqjp_compressed = self.paqjp_compressor.compress_with_best_method(input_data, filetype, input_file, mode=mode)
        paqjp_output = bytes([0x01]) + paqjp_compressed if paqjp_compressed else b''

        # Choose the best (smallest) output
        best_output = None
        if smart_output and paqjp_output:
            best_output = smart_output if len(smart_output) <= len(paqjp_output) else paqjp_output
            logging.info(f"Selected {'Smart Compressor' if best_output[0] == 0x00 else 'PAQJP_6'} with size {len(best_output)} bytes")
        elif smart_output:
            best_output = smart_output
            logging.info(f"Selected Smart Compressor with size {len(smart_output)} bytes")
        elif paqjp_output:
            best_output = paqjp_output
            logging.info(f"Selected PAQJP_6 with size {len(paqjp_output)} bytes")
        else:
            logging.error("Both compression methods failed.")
            return

        with open(output_file, "wb") as f_out:
            f_out.write(best_output)
        orig_size = len(input_data)
        comp_size = len(best_output)
        ratio = (comp_size / orig_size) * 100 if orig_size > 0 else 0
        logging.info(f"Compression successful. Output saved to {output_file}. Size: {comp_size} bytes")
        logging.info(f"Original: {orig_size} bytes, Compressed: {comp_size} bytes, Ratio: {ratio:.2f}%")

    def decompress(self, input_file, output_file):
        """Decompress file based on the marker."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found.")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}.")
            return
        if os.path.getsize(input_file) == 0:
            logging.warning(f"Input file '{input_file}' is empty, writing empty output")
            with open(output_file, 'wb') as f_out:
                f_out.write(b'')
            return

        with open(input_file, "rb") as f:
            data = f.read()

        if len(data) < 1:
            logging.error("Input data too short to contain marker.")
            return

        marker = data[0]
        compressed_data = data[1:]

        if marker == 0x00:
            logging.info("Detected Smart Compressor (marker 00)")
            decompressed = self.smart_compressor.decompress(compressed_data)
        elif marker == 0x01:
            logging.info("Detected PAQJP_6 Compressor (marker 01)")
            decompressed, _ = self.paqjp_compressor.decompress_with_best_method(compressed_data)
        else:
            logging.error(f"Unknown compression marker: {marker:02x}")
            return

        if decompressed is None:
            logging.error("Decompression failed.")
            return

        with open(output_file, "wb") as f_out:
            f_out.write(decompressed)
        comp_size = len(data)
        decomp_size = len(decompressed)
        zero_count = sum(1 for b in decompressed if b == 0)
        logging.info(f"Decompression successful. Output saved to {output_file}, {zero_count} zero bytes in output")
        logging.info(f"Compressed: {comp_size} bytes, Decompressed: {decomp_size} bytes")

def detect_filetype(filename: str) -> Filetype:
    """Detect filetype based on extension."""
    _, ext = os.path.splitext(filename.lower())
    if ext in ['.jpg', '.jpeg']:
        return Filetype.JPEG
    elif ext == '.txt':
        return Filetype.TEXT
    else:
        return Filetype.DEFAULT

def main():
    print("PAQJP_6_Smart Compression System with Dictionary")
    print("Created by Jurijus Pacalovas")
    print("Options:")
    print("1 - Compress file (Best of Smart Compressor [00] or PAQJP_6 [01])")
    print("2 - Decompress file")

    compressor = CombinedCompressor()

    try:
        choice = input("Enter 1 or 2: ").strip()
        if choice not in ('1', '2'):
            logging.error("Invalid choice. Exiting.")
            return
    except (EOFError, KeyboardInterrupt):
        logging.info("Program terminated by user.")
        return

    mode = "slow"
    if choice == '1':
        try:
            mode_choice = input("Enter compression mode (1 for fast, 2 for slow): ").strip()
            if mode_choice == '1':
                mode = "fast"
            elif mode_choice == '2':
                mode = "slow"
            else:
                logging.warning("Invalid mode choice. Defaulting to slow mode.")
                mode = "slow"
        except (EOFError, KeyboardInterrupt):
            logging.info("No mode input detected. Defaulting to slow mode.")
            mode = "slow"
        logging.info(f"Selected compression mode: {mode}")

    input_file = input("Input file name: ").strip()
    output_file = input("Output file name: ").strip()

    if choice == '1':
        compressor.compress(input_file, output_file, mode=mode)
    elif choice == '2':
        compressor.decompress(input_file, output_file)

if __name__ == "__main__":
    main()
