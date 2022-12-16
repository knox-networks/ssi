#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "../headers/ssi_ffi.h"
#include "../src-unity/unity.h"

// manually declare mkdtemp() to satisfy undeclared bug in POSIX env
char* mkdtemp(char*);

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

char* test_create_did_doc(void) {
    // did_method: repr_c::String,
    // mnemonic_input: repr_c::String
    char* did_doc = create_identity(NULL, "DID_METHOD", "")
    return did_doc;
}

void test_push_did_doc(void) {
    char* did_doc = test_create_did_doc()
    // address, did, document
    registry_create_did(NULL, address, "did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ", did_doc)
    const char *currency_code = "USD";
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_push_did_doc);
    return UNITY_END();
}
