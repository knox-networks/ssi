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

DidDocument_t* test_create_did_doc(void) {
    char did_method[] = "DID_METHOD";
    char mnemonic[] = "";
    printf("test_create_did_doc");
    DidDocument_t *did_doc_rsp = create_identity(NULL, did_method, mnemonic);
    TEST_ASSERT_NOT_NULL(did_doc_rsp);
    return did_doc_rsp;
}

void test_push_did_doc_integration(void) {
    DidDocument_t *did_document = test_create_did_doc();
    char address[] = "";
    char did[] = "did:knox:zFCxaFZ4twBFG8P2hBvzheaRdsSshqEngn9r4nuQwEMfJ";
    bool created = registry_create_did(NULL, address, did, did_document);
    TEST_ASSERT_TRUE(created);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_push_did_doc_integration);
    return UNITY_END();
}
