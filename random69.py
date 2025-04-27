import hashlib
import base58
from ecdsa import SECP256k1, SigningKey
import random
import sys
from concurrent.futures import ThreadPoolExecutor

# Define the target Bitcoin addresses as a list
TARGET_ADDRESSES = "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"
  

# Function to derive a compressed Bitcoin address from a private key
def private_key_to_compressed_address(private_key_hex):
    try:
        # Convert the private key from hex string to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Generate the public key using elliptic curve cryptography (ECC)
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        public_key = sk.verifying_key.to_string("compressed").hex()
        
        # Hash the public key to generate the Bitcoin address
        sha256_hash = hashlib.sha256(bytes.fromhex(public_key)).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        hashed_public_key = ripemd160.digest()
        
        # Add network byte (0x00 for mainnet Bitcoin)
        network_byte = b"\x00" + hashed_public_key
        
        # Compute checksum (first 4 bytes of double SHA-256 hash)
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        
        # Encode in Base58 to get the Bitcoin address
        binary_address = network_byte + checksum
        bitcoin_address = base58.b58encode(binary_address).decode('utf-8')
        
        return bitcoin_address, public_key
    except Exception as e:
        print(f"Error generating compressed address: {e}")
        return None, None

# Function to perform randomized brute-force search in a single thread
def random_brute_force_thread(start, end, total_tests_per_thread):
    for i in range(total_tests_per_thread):
        # Generate a random private key within the range
        private_key_int = random.randint(start, end)
        private_key_hex = f"{private_key_int:064x}"  # Convert to 64-character hex string
        bitcoin_address, public_key = private_key_to_compressed_address(private_key_hex)
        
        # Update progress dynamically (every 100,000 iterations)
        if i % 1 == 0:
            progress = (i + 1) / total_tests_per_thread * 100
            sys.stdout.write(f"\rThread {id}: Progress: {progress:.2f}% | Testing private key: {private_key_hex}")
            sys.stdout.flush()
        
        # Check if the derived Bitcoin address matches any of the target addresses
        if bitcoin_address in TARGET_ADDRESSES:
            print(f"\nPrivate key found: {private_key_hex}")
            print(f"Bitcoin address: {bitcoin_address}")
            return private_key_hex
    
    print(f"\nThread completed. Private key not found.")
    return None

# Main function to execute the brute-force search with multiple threads
if __name__ == "__main__":
    # Define the range of private keys to search (for Puzzle #71)
    START_KEY = 0x100000000000000000  # Start of the range for Puzzle #71
    END_KEY = 0x1fffffffffffffffff    # End of the range for Puzzle #71
    
    # Total number of random tests across all threads
    TOTAL_TESTS = 10000000  # 10 million random tests
    
    # Number of threads
    NUM_THREADS = 2
    
    # Divide the total tests among the threads
    TESTS_PER_THREAD = TOTAL_TESTS // NUM_THREADS
    
    # Perform the random brute-force search using multiple threads
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = []
        for _ in range(NUM_THREADS):
            future = executor.submit(random_brute_force_thread, START_KEY, END_KEY, TESTS_PER_THREAD)
            futures.append(future)
        
        # Wait for all threads to complete and check results
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)  # Exit early if a private key is found
    
    print("Search completed. Private key not found.")