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
    DidDocument_t *did_doc_rsp = create_identity(NULL, did_method, mnemonic);
    TEST_ASSERT_NOT_NULL(did_doc_rsp);
    return did_doc_rsp;
}

void test_push_did_doc_integration(void) {
    DidDocument_t *did_document = test_create_did_doc();
    printf("\n test_create_did_doc did_document received \n");
    char address[] = "https://reg.sandbox5.knoxnetworks.io";
    char did[] = "did:knox:z4nmbV2RC3Th1DLPRYVkJUSzv3HSegexgUcvS3WTZGfU4";
    bool created = registry_create_did(NULL, address, did, did_document);
    TEST_ASSERT_TRUE(created);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_push_did_doc_integration);
    return UNITY_END();
}
