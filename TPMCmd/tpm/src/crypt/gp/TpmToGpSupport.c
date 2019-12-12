#include <tee_internal_api.h>

#define AES_BLOCK_SIZE 16

int
AES_set_encrypt_key_GP(
    const unsigned char *key,
    const int keySize,
    TEE_OperationHandle *op
    )
{
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    TEE_Result res;

    //IMSG("ENTER SET ENC key");

    //if (*op != TEE_HANDLE_NULL)
    //    TEE_FreeOperation(*op);

    res = TEE_AllocateOperation(&op_handle,
                    TEE_ALG_AES_ECB_NOPAD,
                    TEE_MODE_ENCRYPT,
                    keySize);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation, %x", res);
        return -1;
    }

    //IMSG("allocated operation\n");

    /* Allocate transient object according to target key size */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES,
                      keySize,
                      &key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object %x", res);
        key_handle = TEE_HANDLE_NULL;
        return -1;
    }

    //IMSG("allocated object\n");

    // then set the key
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keySize/8);

    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_PopulateTransientObject failed, %x", res);
        return -1;
    }

    //IMSG("init attribute\n");

    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed %x", res);
        return -1;
    }

    //IMSG("set key\n");

    // initialize the operation without any IV (ECB mode)
    TEE_CipherInit(op_handle, NULL, 0);
    *op = op_handle;

    //IMSG("init cipher\n");

    // free the key handle
	TEE_FreeTransientObject(key_handle);

    //IMSG("***EXIT SET ENC key\n");

    return 0;
}


int
AES_set_decrypt_key_GP(
    const unsigned char *key,
    const int keySize,
    TEE_OperationHandle *op
    )
{
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_Attribute attr;
    TEE_Result res;

    //IMSG("***ENTER SET DEC key");

    //if (*op != TEE_HANDLE_NULL)
    //    TEE_FreeOperation(*op);

    res = TEE_AllocateOperation(&op_handle,
                    TEE_ALG_AES_ECB_NOPAD,
                    TEE_MODE_DECRYPT,
                    keySize);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation %x", res);
        return -1;
    }

    //IMSG("allocated operation\n");

    /* Allocate transient object according to target key size */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES,
                      keySize,
                      &key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate transient object");
        key_handle = TEE_HANDLE_NULL;
        return -1;
    }

    //IMSG("allocated object\n");

    // then set the key
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keySize/8);

    res = TEE_PopulateTransientObject(key_handle, &attr, 1);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_PopulateTransientObject failed, %x", res);
        return -1;
    }

    //IMSG("init attribute\n");

    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed %x", res);
        return -1;
    }

    //IMSG("set key\n");

    // initialize the operation without any IV (ECB mode)
    TEE_CipherInit(op_handle, NULL, 0);
    *op = op_handle;

    //("init cipher\n");

    // free the key handle
	TEE_FreeTransientObject(key_handle);

    //IMSG("***EXIT SET DEC key\n");

    return 0;
}


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
    )
{
	TEE_Result res;
    unsigned char input[AES_BLOCK_SIZE] = {0};
    unsigned char output[AES_BLOCK_SIZE];
    size_t size = AES_BLOCK_SIZE;

    //IMSG("enter encrypt\n");
    memcpy(input, in, AES_BLOCK_SIZE);

    //TEE_OperationInfo info;

    // TEE_GetOperationInfo(op, &info);
    // IMSG("first info %d %d %d %d %d %d %d %d\n",info.algorithm, info.operationClass, info.mode, info.digestLength, info.maxKeySize, info.keySize, info.requiredKeyUsage, info.handleState);
    // TEE_GetOperationInfo(*op, &info);
    // IMSG("first info %d %d %d %d %d %d %d %d\n",info.algorithm, info.operationClass, info.mode, info.digestLength, info.maxKeySize, info.keySize, info.requiredKeyUsage, info.handleState);

    res = TEE_CipherUpdate(*op,
				input, AES_BLOCK_SIZE,
				output, &size);
    //IMSG("size output: %d\n",size);


    if (res != TEE_SUCCESS) {
        EMSG("TEE_CipherUpdate failed %x", res);
        return;
    }

    memcpy(out, output, size);
    //IMSG("exit encrypt\n");
}



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
    )
{
    TEE_Result res;
    unsigned char input[AES_BLOCK_SIZE] = {0};
    unsigned char output[AES_BLOCK_SIZE];
    size_t size = AES_BLOCK_SIZE;

    //IMSG("enter decrypt\n");
    memcpy(input, in, AES_BLOCK_SIZE);

    res = TEE_CipherUpdate(*op,
				input, AES_BLOCK_SIZE,
				output, &size);

    if (res != TEE_SUCCESS) {
        EMSG("TEE_CipherUpdate failed %x", res);
        return;
    }

    memcpy(out, output, AES_BLOCK_SIZE);
    //IMSG("exit decrypt\n");
}
