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

void test_create_did_doc(void) {
    char did_doc[] = "DID_METHOD";
    char address[] = "";
    printf("test_create_did_doc");
    DidDocument_t *did_doc_rsp = create_identity(NULL, did_doc, address);
    TEST_ASSERT_NOT_NULL(did_doc_rsp);
}

// void test_push_did_doc(void) {
//     Vec_uint8_t did_doc = test_create_did_doc();
//     // address, did, document
//     registry_create_did(NULL, address, "did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ", did_doc)
// }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_did_doc);
    return UNITY_END();
}
