// Add these to the test_cases array:
static const test_case test_cases[] = {
    // ... existing tests ...
    
    // Long message test (1,000,000 repetitions of "a")
    {
        "", // We'll handle this specially
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        "1,000,000 repetitions of 'a'"
    },
    
    // Test from RFC 4634
    {
        "68656c6c6f20776f726c64", // "hello world" in hex
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "hello world"
    },
    
    // Exactly one block (64 bytes) of 0x00
    {
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8",
        "64 bytes of zeros"
    },
    
    // Two blocks (128 bytes) of 0x00
    {
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000",
        "fc99a2df88f42a7a7bb9d18033cdc6a20256755f9d5b9a5044a9cc315abe84a7",
        "128 bytes of zeros"
    }
};