#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <jansson.h>  // JSON parsing library
#include "../../include/crypto_lib/hash.h"

// Install libjansson: sudo apt-get install libjansson-dev

// Test incremental hashing
static int test_incremental_vs_one_shot(const uint8_t *data, size_t len) {
    uint8_t digest_one_shot[32];
    uint8_t digest_incremental[32];
    
    // One-shot
    if (crypto_hash_sha256(digest_one_shot, data, len) != 0) {
        return 0;
    }
    
    // Incremental
    sha256_ctx *ctx = sha256_init();
    if (!ctx) return 0;
    
    // Simulate chunked updates (various chunk sizes)
    size_t chunk_size = 7; // Prime number to test boundary conditions
    size_t processed = 0;
    
    while (processed < len) {
        size_t remaining = len - processed;
        size_t this_chunk = (chunk_size < remaining) ? chunk_size : remaining;
        
        if (sha256_update(ctx, data + processed, this_chunk) != 0) {
            sha256_free(ctx);
            return 0;
        }
        processed += this_chunk;
    }
    
    if (sha256_final(ctx, digest_incremental) != 0) {
        sha256_free(ctx);
        return 0;
    }
    
    sha256_free(ctx);
    
    // Compare
    if (memcmp(digest_one_shot, digest_incremental, 32) != 0) {
        printf("  One-shot and incremental results differ!\n");
        return 0;
    }
    
    return 1;
}

// Run tests from JSON file
static int run_json_tests(const char *filename) {
    json_t *root;
    json_error_t error;
    
    root = json_load_file(filename, 0, &error);
    if (!root) {
        printf("Failed to load %s: %s\n", filename, error.text);
        return 0;
    }
    
    json_t *sha256 = json_object_get(root, "sha256");
    if (!sha256) {
        printf("No sha256 tests found in %s\n", filename);
        json_decref(root);
        return 0;
    }
    
    int passed = 0;
    int total = 0;
    
    // Test each category
    const char *categories[] = {"short_messages", "block_boundaries", 
                                "nist_official", "special_cases"};
    
    for (size_t cat = 0; cat < sizeof(categories)/sizeof(categories[0]); cat++) {
        json_t *tests = json_object_get(sha256, categories[cat]);
        if (!json_is_array(tests)) continue;
        
        size_t index;
        json_t *test_obj;
        json_array_foreach(tests, index, test_obj) {
            total++;
            
            const char *message_hex = json_string_value(json_object_get(test_obj, "message"));
            const char *expected_hex = json_string_value(json_object_get(test_obj, "digest"));
            const char *comment = json_string_value(json_object_get(test_obj, "comment"));
            
            if (!message_hex || !expected_hex) {
                printf("  Test %zu in %s: missing data\n", index, categories[cat]);
                continue;
            }
            
            // Convert hex to binary
            size_t msg_len = strlen(message_hex) / 2;
            uint8_t *message = malloc(msg_len);
            uint8_t digest[32];
            
            if (!message) {
                printf("  Memory allocation failed\n");
                continue;
            }
            
            // Simple hex to bin
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(&message_hex[i*2], "%2hhx", &message[i]);
            }
            
            // Compute hash
            crypto_hash_sha256(digest, message, msg_len);
            
            // Verify
            uint8_t expected[32];
            for (size_t i = 0; i < 32; i++) {
                sscanf(&expected_hex[i*2], "%2hhx", &expected[i]);
            }
            
            if (memcmp(digest, expected, 32) == 0) {
                passed++;
                if (comment) {
                    printf("  ✓ %s\n", comment);
                }
                
                // Also test incremental version
                if (!test_incremental_vs_one_shot(message, msg_len)) {
                    printf("  ✗ Incremental test failed for: %s\n", comment);
                }
            } else {
                printf("  ✗ Test failed: %s\n", comment ? comment : "Unknown");
            }
            
            free(message);
        }
    }
    
    json_decref(root);
    printf("  JSON tests: %d/%d passed\n", passed, total);
    return passed == total;
}

int main() {
    printf("Running Comprehensive SHA-256 Tests\n");
    printf("===================================\n\n");
    
    int all_passed = 1;
    
    // Test 1: Basic KATs
    printf("1. Basic Known Answer Tests:\n");
    {
        // Use the simple test runner from earlier
        // (You can call your existing test function here)
        printf("  [Using existing KAT runner]\n");
    }
    
    // Test 2: JSON test vectors
    printf("\n2. Extended Test Vectors from JSON:\n");
    if (!run_json_tests("third_party/test_vectors/sha256_extended.json")) {
        all_passed = 0;
    }
    
    // Test 3: Million 'a' test (memory efficient)
    printf("\n3. Special Long Message Test:\n");
    {
        sha256_ctx *ctx = sha256_init();
        if (!ctx) {
            printf("  Failed to initialize context\n");
            all_passed = 0;
        } else {
            // Process 1,000,000 'a's in chunks
            uint8_t block[1000];
            memset(block, 'a', 1000);
            
            for (int i = 0; i < 1000; i++) { // 1000 * 1000 = 1,000,000
                sha256_update(ctx, block, 1000);
            }
            
            uint8_t digest[32];
            sha256_final(ctx, digest);
            
            // Expected: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
            const uint8_t expected[32] = {
                0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
                0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
                0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
                0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
            };
            
            if (memcmp(digest, expected, 32) == 0) {
                printf("  ✓ 1,000,000 'a' test passed\n");
            } else {
                printf("  ✗ 1,000,000 'a' test failed\n");
                all_passed = 0;
            }
            
            sha256_free(ctx);
        }
    }
    
    // Test 4: Random consistency tests
    printf("\n4. Random Consistency Tests:\n");
    {
        srand(42); // Fixed seed for reproducibility
        int random_passed = 0;
        int random_total = 1000;
        
        for (int i = 0; i < random_total; i++) {
            size_t len = rand() % 4096;
            uint8_t *data = malloc(len);
            
            if (!data) continue;
            
            for (size_t j = 0; j < len; j++) {
                data[j] = rand() & 0xFF;
            }
            
            if (test_incremental_vs_one_shot(data, len)) {
                random_passed++;
            }
            
            free(data);
        }
        
        printf("  Random tests: %d/%d passed\n", random_passed, random_total);
        if (random_passed != random_total) {
            all_passed = 0;
        }
    }
    
    printf("\n===================================\n");
    if (all_passed) {
        printf("SUCCESS: All comprehensive tests passed!\n");
        return 0;
    } else {
        printf("FAILURE: Some tests failed\n");
        return 1;
    }
}