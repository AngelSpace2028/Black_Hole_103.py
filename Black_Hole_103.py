import os
import sys
import logging
import hashlib
import paq

# === Configure Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# === Dictionary file list ===
DICTIONARY_FILES = [
    "eng_news_2005_1M-sentences.txt", "eng_news_2005_1M-words.txt",
    "eng_news_2005_1M-sources.txt", "eng_news_2005_1M-co_n.txt",
    "eng_news_2005_1M-co_s.txt", "eng_news_2005_1M-inv_so.txt",
    "eng_news_2005_1M-meta.txt", "Dictionary.txt",
    "the-complete-reference-html-css-fifth-edition.txt",
    "words.txt.paq", "lines.txt.paq", "sentence.txt.paq"
]

# === Smart Compressor ===
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
                            return filename
            except Exception as e:
                logging.warning(f"Error searching {filename}: {e}")
        return None

    def zlib_compress(self, data):
        """Compress data using zlib (lossless)."""
        logging.info("Starting zlib compression...")
        try:
            compressed = paq.compress(data)
            logging.info("Zlib compression complete.")
            return compressed
        except Exception as e:
            logging.error(f"Zlib compression failed: {e}")
            raise

    def zlib_decompress(self, data):
        """Decompress data using zlib (lossless)."""
        logging.info("Starting zlib decompression...")
        try:
            decompressed = paq.decompress(data)
            logging.info("Zlib decompression complete.")
            return decompressed
        except Exception as e:
            logging.error(f"Zlib decompression failed: {e}")
            raise

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

    def generate_8byte_sha(self, file_path):
        """Generate first 8 bytes of SHA-256 hash for a file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                full_hash = hashlib.sha256(data).digest()
                return full_hash[:8]
        except Exception as e:
            logging.error(f"Failed to generate SHA for {file_path}: {e}")
            return None

    def compress(self, input_file, output_file):
        """Compress a file with hash verification using zlib."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found.")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}.")
            return

        try:
            with open(input_file, "rb") as f:
                original_data = f.read()
        except Exception as e:
            logging.error(f"Failed to read {input_file}: {e}")
            return

        original_hash = self.compute_sha256(original_data)
        logging.info(f"SHA-256 of input: {original_hash}")

        # Check if hash exists in dictionaries
        found = self.find_hash_in_dictionaries(original_hash)
        if found:
            logging.info(f"Hash found in dictionary: {found}")
        else:
            logging.info("Hash not found in any dictionary. Proceeding with lossless compression.")

        # Special case for .paq dictionary files
        if input_file.endswith(".paq") and any(x in input_file for x in ["words", "lines", "sentence"]):
            sha = self.generate_8byte_sha(input_file)
            if sha:
                original_size = os.path.getsize(input_file)
                if 8 < original_size:
                    try:
                        with open(output_file, "wb") as f:
                            f.write(sha)
                        logging.info(f"SHA-8 written to {output_file}: {sha.hex()}")
                    except Exception as e:
                        logging.error(f"Failed to write {output_file}: {e}")
                else:
                    logging.info("Original file smaller than SHA hash, skipping write.")
            return

        # Normal compression flow (lossless)
        transformed = self.reversible_transform(original_data)
        try:
            compressed = self.zlib_compress(transformed)
        except Exception:
            return

        if len(compressed) < len(original_data):
            try:
                with open(output_file, "wb") as f:
                    f.write(self.compute_sha256_binary(original_data))  # 32-byte hash
                    f.write(compressed)
                logging.info(f"Smart compression successful. Saved to {output_file}")
                logging.info(f"Original size: {len(original_data)} bytes, Compressed size: {len(compressed)} bytes")
            except Exception as e:
                logging.error(f"Failed to write {output_file}: {e}")
        else:
            logging.info("Compression not efficient. File not saved.")

    def decompress(self, input_file, output_file):
        """Decompress a file with hash verification."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found.")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}.")
            return

        try:
            with open(input_file, "rb") as f:
                stored_hash = f.read(32)  # Read 32-byte SHA-256 hash
                compressed_data = f.read()
        except Exception as e:
            logging.error(f"Failed to read {input_file}: {e}")
            return

        try:
            decompressed = self.zlib_decompress(compressed_data)
        except Exception:
            return
        original = self.reverse_reversible_transform(decompressed)

        computed_hash = self.compute_sha256_binary(original)
        if computed_hash == stored_hash:
            logging.info("Hash verification successful.")
        else:
            logging.error("Hash verification failed! Data may be corrupted.")
            return

        try:
            with open(output_file, "wb") as f:
                f.write(original)
            logging.info(f"Smart decompression complete. Saved to {output_file}")
        except Exception as e:
            logging.error(f"Failed to write {output_file}: {e}")

# === Main Menu ===
def main():
    print("Created by Jurijus Pacalovas")
    print("Using Smart Compressor (Zlib + Reversible)")
    
    compressor = SmartCompressor()
    print("1. Compress\n2. Decompress")
    try:
        action = input("Select action: ").strip()
    except KeyboardInterrupt:
        logging.info("Program terminated by user.")
        sys.exit(0)
    
    if action == "1":
        i = input("Input file: ").strip()
        o = input("Output file: ").strip()
        compressor.compress(i, o)
    elif action == "2":
        i = input("Compressed file: ").strip()
        o = input("Output file: ").strip()
        compressor.decompress(i, o)
    else:
        logging.error("Invalid action. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
