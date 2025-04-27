import hashlib
import base58
from ecdsa import SECP256k1, SigningKey
import sys
from concurrent.futures import ThreadPoolExecutor

# Define the target Bitcoin addresses as a list
TARGET_ADDRESSES = [
    "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG",
    "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR",
]

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

# Function to perform sequential brute-force search in a single thread
def sequential_brute_force_thread(start, end):
    for private_key_int in range(start, end + 1):
        private_key_hex = f"{private_key_int:064x}"  # Convert to 64-character hex string
        bitcoin_address, public_key = private_key_to_compressed_address(private_key_hex)
        
        # Update progress dynamically (every 100,000 iterations)
        if private_key_int % 10000 == 0:
            progress = (private_key_int - start) / (end - start + 1) * 100
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
    END_KEY = 0xffffffffffffffffff    # End of the range for Puzzle #71
    
    # Number of threads
    NUM_THREADS = 8
    
    # Divide the range into equal segments for each thread
    range_size = (END_KEY - START_KEY + 1) // NUM_THREADS
    ranges = [(START_KEY + i * range_size, START_KEY + (i + 1) * range_size - 1) for i in range(NUM_THREADS)]
    
    # Handle any leftover keys by assigning them to the last thread
    ranges[-1] = (ranges[-1][0], END_KEY)
    
    # Perform the sequential brute-force search using multiple threads
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = []
        for i, (start, end) in enumerate(ranges):
            future = executor.submit(sequential_brute_force_thread, start, end)
            futures.append(future)
        
        # Wait for all threads to complete and check results
        for future in futures:
            result = future.result()
            if result:
                print(f"Found private key: {result}")
                sys.exit(0)  # Exit early if a private key is found
    
    print("Search completed. Private key not found.")