/*! \file */
/*******************************************
 *                                         *
 *  File auto-generated by `::safer_ffi`.  *
 *                                         *
 *  Do not manually edit this file.        *
 *                                         *
 *******************************************/

#ifndef __RUST_SSI_FFI__
#define __RUST_SSI_FFI__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RustError {

    char * error_str;

} RustError_t;

typedef struct DidDocument DidDocument_t;


#include <stdbool.h>

bool registry_create_did (
    RustError_t * rust_error,
    char const * address,
    char const * did,
    DidDocument_t * document);

void free_rust_error (
    RustError_t rust_error);

DidDocument_t * create_identity (
    RustError_t * rust_error,
    char const * did_method,
    char const * mnemonic_input);


#include <stddef.h>
#include <stdint.h>

/** \brief
 *  Same as [`Vec<T>`][`rust::Vec`], but with guaranteed `#[repr(C)]` layout
 */
typedef struct Vec_uint8 {

    uint8_t * ptr;

    size_t len;

    size_t cap;

} Vec_uint8_t;

Vec_uint8_t * create_identity_vec (
    RustError_t * rust_error,
    char const * did_method,
    char const * mnemonic_input);

void free_identity_did_doc (
    DidDocument_t * did_doc);

typedef struct KeyPair KeyPair_t;

KeyPair_t * create_keypair (
    RustError_t * rust_error,
    char const * did_method);

KeyPair_t * recover_keypair (
    RustError_t * rust_error,
    char const * did_method,
    char const * mnemonic_input);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __RUST_SSI_FFI__ */
