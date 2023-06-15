#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "../headers/ssi_ffi.h"
#include "../src-unity/unity.h"

// manually declare mkdtemp() to satisfy undeclared bug in POSIX env
char *mkdtemp(char *);

void setUp(void)
{
    // set stuff up here
}

void tearDown(void)
{
    // clean stuff up here
}

DidDocument_t *create_did_doc(void)
{
    char did_method[] = "DID_METHOD";
    char mnemonic[] = "";
    DidDocument_t *did_doc_rsp = create_identity(NULL, did_method, mnemonic);
    TEST_ASSERT_NOT_NULL(did_doc_rsp);
    return did_doc_rsp;
}

void test_create_did_doc_vecs(void)
{
    char did_method[] = "DID_METHOD";
    char mnemonic[] = "";
    Vec_uint8_t *did_doc_rsp = create_identity_vec(NULL, did_method, mnemonic);
    TEST_ASSERT_NOT_NULL(did_doc_rsp);
}

void test_push_did_doc_integration(void)
{
    DidDocument_t *did_document = create_did_doc();
    printf("\n test_create_did_doc did_document received \n");
    char address[] = "https://reg.integration.knoxnetworks.io";
    char did[] = "did:knox:z4nmbV2RC3Th1DLPRYVkJUSzv3HSegexgUcvS3WTZGfU4";
    bool created = registry_create_did(NULL, address, did, did_document);
    TEST_ASSERT_TRUE(created);
}

void test_create_key_pair(void)
{
    FFICompatEd25519KeyPair_t *key_pair = create_keypair(NULL, "DID_METHOD");
    TEST_ASSERT_NOT_NULL(key_pair);
}

void test_recover_key_pair(void)
{
    FFICompatEd25519KeyPair_t *key_pair_recovered = recover_keypair(NULL, "DID_METHOD", "become family fame will sting grain turn south sick song sunny miracle cloud unfold climb giant useful crunch near need vast regret stadium language");
    TEST_ASSERT_NOT_NULL(key_pair_recovered);
    TEST_ASSERT_NOT_NULL(key_pair_recovered->mnemonic.phrase);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_did_doc_vecs);
    RUN_TEST(test_push_did_doc_integration);
    RUN_TEST(test_create_key_pair);
    return UNITY_END();
}
