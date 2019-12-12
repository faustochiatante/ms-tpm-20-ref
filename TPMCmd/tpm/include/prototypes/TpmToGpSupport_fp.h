#include <tee_internal_api.h>

/**
 * set the encryption key inside the operation op
 * @param key     [description]
 * @param keySize [description]
 * @param op      [description]
 */
int
AES_set_encrypt_key_GP(
    const unsigned char *key,
    const int keySize,
    TEE_OperationHandle *op
);


/**
 * set the decryption key inside the operation op
 * @param key     [description]
 * @param keySize [description]
 * @param op      [description]
 */
int
AES_set_decrypt_key_GP(
    const unsigned char *key,
    const int keySize,
    TEE_OperationHandle *op
);


/**
 * encrypt the single block message in using the symmetric cipher op
 * @param in  [description]
 * @param out [description]
 * @param op  [description]
 */
void
AES_encrypt_GP (
    const unsigned char *in,
    unsigned char *out,
    TEE_OperationHandle *op
);



/**
 * decrypt the single block message in using the symmetric cipher op
 * @param in  [description]
 * @param out [description]
 * @param op  [description]
 */
void
AES_decrypt_GP (
    const unsigned char *in,
    unsigned char *out,
    TEE_OperationHandle *op
);
