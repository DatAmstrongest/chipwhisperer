import chipwhisperer as cw
import time
import sys
import binascii

def parse_kat_file(filepath):
    kats = []
    current_kat = {}
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if '=' in line:
                    key, val = line.split('=', 1)
                    key = key.strip()
                    val = val.strip()
                    
                    if key == 'Count':
                        if current_kat:
                            kats.append(current_kat)
                        current_kat = {}
                    
                    current_kat[key] = val

            if current_kat:
                kats.append(current_kat)
                
    except FileNotFoundError:
        print(f"Error: Could not find file '{filepath}'")
        sys.exit(1)

    return kats

def send_data_chunked(target, command, data, chunk_size=16):
    if len(data) == 0:
        # Send empty chunk
        target.simpleserial_write(command, bytearray([0] * chunk_size))
        return
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        # Pad last chunk to chunk_size
        if len(chunk) < chunk_size:
            chunk = chunk + bytearray([0] * (chunk_size - len(chunk)))
        target.simpleserial_write(command, chunk)
        time.sleep(0.01)

def main():
    # --- 1. Configuration ---
    kat_path = "LWC_AEAD_KAT_128_128.txt"
    fw_path = "./simpleserial-ascon-CWHUSKY.hex"

    # --- 2. Connect & Setup ---
    try:
        scope = cw.scope()
        target = cw.target(scope)
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    print("Found ChipWhisperer!")
    scope.default_setup()
    
    if hasattr(scope.io, 'target_pwr'):
        scope.io.target_pwr = 'high'
    
    print(f"Programming: {fw_path}")
    cw.program_target(scope, cw.programmers.SAM4SProgrammer, fw_path)
    
    # Hard reset
    print("Resetting target...")
    scope.io.nrst = 'low'
    time.sleep(0.05)
    scope.io.nrst = 'high'
    time.sleep(0.3)
    
    target.flush()

    # --- 3. Parse KAT File ---
    print(f"Parsing KAT file: {kat_path}...")
    kats = parse_kat_file(kat_path)
    print(f"Loaded {len(kats)} test vectors.")

    print("\n--- Starting KAT Verification ---\n")

    pass_count = 0
    fail_count = 0

    for kat in kats:
        count = kat.get("Count", "Unknown")
        
        # Convert hex strings to bytearrays
        key = bytearray.fromhex(kat.get("Key", ""))
        nonce = bytearray.fromhex(kat.get("Nonce", ""))
        pt_real = bytearray.fromhex(kat.get("PT", ""))
        ad_real = bytearray.fromhex(kat.get("AD", ""))
        expected_ct = kat.get("CT", "").lower()

        # Check if data fits in firmware buffers (256 bytes max)
        if len(ad_real) > 255 or len(pt_real) > 255:
            print(f"Count {count}: SKIP (Data exceeds firmware buffer size)")
            continue
        
        # --- Protocol Communication ---
        
        # 1. Send Key & Nonce
        target.simpleserial_write('k', key)
        time.sleep(0.01)
        target.simpleserial_write('n', nonce)
        time.sleep(0.01)

        # 2. Send Length Configuration
        len_config = bytearray([len(ad_real), len(pt_real)]) + bytearray([0] * 14)
        target.simpleserial_write('l', len_config)
        time.sleep(0.01)

        # 3. Send AD in 16-byte chunks
        send_data_chunked(target, 'a', ad_real, 16)

        # 4. Arm scope and send PT in 16-byte chunks
        scope.arm()
        send_data_chunked(target, 'p', pt_real, 16)

        # 5. Capture Trace
        ret = scope.capture()
        if ret:
            print(f"Count {count}: FAIL (Timeout)")
            fail_count += 1
            continue

        # 6. Read Response
        expected_response_len = len(pt_real) + 16
        
        try:
            response = target.simpleserial_read('r', expected_response_len, timeout=1000)
            
            if response is None:
                print(f"Count {count}: FAIL (No response)")
                fail_count += 1
                continue
                
            response_hex = binascii.hexlify(response).decode()

            # 7. Verify
            if response_hex == expected_ct:
                print(f"Count {count}: PASS")
                pass_count += 1
            else:
                print(f"Count {count}: FAIL")
                print(f"   PT: {len(pt_real)}B, AD: {len(ad_real)}B")
                print(f"   Expected: {expected_ct}")
                print(f"   Got:      {response_hex}")
                fail_count += 1
                
        except Exception as e:
            print(f"Count {count}: FAIL (Exception: {e})")
            fail_count += 1

        time.sleep(0.05)

    # Summary
    print("\n" + "="*60)
    print(f"KAT Verification Complete")
    print(f"PASS: {pass_count}/{len(kats)}")
    print(f"FAIL: {fail_count}/{len(kats)}")
    if pass_count == len(kats):
        print("✓ ALL TESTS PASSED!")
    print("="*60)

    # Cleanup
    scope.dis()
    target.dis()

if __name__ == "__main__":
    main()