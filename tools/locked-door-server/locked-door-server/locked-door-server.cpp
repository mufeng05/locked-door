#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/applink.c>

#define BLOCK_SIZE 256
#define ROUNDS 14

// RAII 包装器用于 OpenSSL 对象
struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* p) { EVP_PKEY_free(p); } };
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;

struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX* p) { EVP_MD_CTX_free(p); } };
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

struct OSSL_PARAM_Deleter { void operator()(OSSL_PARAM* p) { OPENSSL_free(p); } };
using OSSL_PARAM_ptr = std::unique_ptr<OSSL_PARAM, OSSL_PARAM_Deleter>;

// 错误处理
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// 生成 RSA 密钥对
EVP_PKEY_ptr generateRSAKeyPair(size_t bits = 2048) {
    EVP_PKEY_ptr pkey(EVP_PKEY_new());
    if (!pkey) handleErrors();

    // EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

    // 设置密钥长度
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits),
        OSSL_PARAM_END
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) handleErrors();

    EVP_PKEY* rawPkey = nullptr;
    if (EVP_PKEY_generate(ctx, &rawPkey) <= 0) handleErrors();
    pkey.reset(rawPkey);

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// 签名消息
std::vector<unsigned char> signMessage(const std::string& message, EVP_PKEY* pkey) {
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) handleErrors();

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        handleErrors();
    }

    if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) <= 0) {
        handleErrors();
    }

    size_t siglen;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &siglen) <= 0) {
        handleErrors();
    }

    std::vector<unsigned char> signature(siglen);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &siglen) <= 0) {
        handleErrors();
    }

    signature.resize(siglen);
    return signature;
}

// 验证签名
bool verifySignature(const std::string& message,
    const std::vector<unsigned char>& signature,
    EVP_PKEY* pkey) {
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) handleErrors();

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        handleErrors();
    }

    if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) <= 0) {
        handleErrors();
    }

    int ret = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (ret < 0) handleErrors();

    return ret == 1;
}

// 保存密钥到文件
void saveKeyToFile(EVP_PKEY* pkey, const std::string& filename, bool isPrivate) {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        std::cerr << "无法打开文件 " << filename << " 进行写入" << std::endl;
        return;
    }

    if (isPrivate) {
        if (!PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            fclose(fp);
            handleErrors();
        }
    }
    else {
        if (!PEM_write_PUBKEY(fp, pkey)) {
            fclose(fp);
            handleErrors();
        }
    }

    fclose(fp);
}

void saveSigToFile(std::vector<unsigned char> signature, const std::string& filename) {
    FILE* fp = fopen(filename.c_str(), "wb");
	if (!fp) {
		std::cerr << "无法打开文件 " << filename << " 进行写入" << std::endl;
		return;
	}
	fwrite(signature.data(), sizeof(unsigned char), signature.size(), fp);

    fclose(fp);
}

void saveAESToFile(uint8_t *text, const std::string& filename,size_t size) {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        std::cerr << "无法打开文件 " << filename << " 进行写入" << std::endl;
        return;
    }
	fwrite(text, sizeof(uint8_t), size, fp);

    fclose(fp);
}

// 从文件加载密钥
EVP_PKEY_ptr loadKeyFromFile(const std::string& filename, bool isPrivate) {
    FILE* fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        std::cerr << "无法打开文件 " << filename << " 进行读取" << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (isPrivate) {
        pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    }
    else {
        pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    }

    fclose(fp);

    if (!pkey) handleErrors();
    return EVP_PKEY_ptr(pkey);
}

void printKey(EVP_PKEY* pkey, bool isPrivate) {
    if (isPrivate) {
        PEM_write_PrivateKey(stdout, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    }
    else {
		PEM_write_PUBKEY(stdout, pkey);
    }
}

// 打印十六进制
void printHex(const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        printf("%02x", byte);
    }
    printf("\n");
}



uint8_t sbox[256] = {
    0x20, 0x39, 0x1D, 0xA2, 0x22, 0x70, 0xB0, 0xA1, 0x90, 0xEE, 0xF4, 0xC3, 0x2B, 0x48, 0x56, 0x4E,
    0xA6, 0xD2, 0xD1, 0x9A, 0x2C, 0x3E, 0xA0, 0x83, 0xB2, 0xF7, 0xB5, 0x99, 0x26, 0x03, 0xBD, 0xEA,
    0x4C, 0xC2, 0x89, 0x8C, 0x61, 0x24, 0xA4, 0xCC, 0x31, 0x7F, 0x5F, 0x7B, 0x02, 0xF9, 0x28, 0x86,
    0x8A, 0xFD, 0x79, 0x8B, 0x4F, 0x30, 0x12, 0x9E, 0xF1, 0x5A, 0x63, 0x3D, 0x43, 0xDB, 0x21, 0xC1,
    0x2F, 0xF2, 0x1C, 0x52, 0xCE, 0xDF, 0x18, 0x82, 0x9B, 0x0C, 0xDD, 0x16, 0xDC, 0x51, 0xF6, 0x41,
    0x78, 0x91, 0xAB, 0xBB, 0x6F, 0x36, 0x2D, 0xD0, 0x65, 0x00, 0x42, 0x96, 0x08, 0xA5, 0x5D, 0xAA,
    0xAE, 0xC4, 0x1F, 0x77, 0x14, 0x72, 0xB7, 0xFC, 0x60, 0x6C, 0xC6, 0xAD, 0xCD, 0x3B, 0xBF, 0x9F,
    0xA8, 0x9D, 0x9C, 0xB4, 0x38, 0x7C, 0xFE, 0xD6, 0xB8, 0x1E, 0x0B, 0x3F, 0xAF, 0x68, 0x80, 0xCB,
    0xD5, 0x1A, 0x47, 0x6E, 0x5C, 0x17, 0xB1, 0xB3, 0x76, 0x93, 0x01, 0x97, 0xA3, 0xF3, 0x33, 0xD9,
    0x10, 0x8E, 0x84, 0x0E, 0xC0, 0x53, 0x87, 0xB9, 0xED, 0x50, 0x95, 0xFF, 0xEC, 0x3A, 0x6A, 0x57,
    0xD3, 0xF8, 0x06, 0xB6, 0xEF, 0x4D, 0x8F, 0x45, 0xE5, 0x74, 0x29, 0x54, 0x1B, 0xDA, 0x3C, 0x07,
    0x4B, 0x23, 0x49, 0x34, 0x7A, 0x88, 0x67, 0xFB, 0x71, 0x94, 0x27, 0xE8, 0x64, 0xCA, 0x0D, 0xC9,
    0xE3, 0xD8, 0x58, 0x05, 0x66, 0xE4, 0x59, 0xE0, 0xE1, 0x46, 0xA7, 0x0F, 0x6D, 0xD4, 0x92, 0x40,
    0xC7, 0xE9, 0x8D, 0xCF, 0x6B, 0x35, 0x7E, 0xFA, 0x04, 0x11, 0x62, 0x85, 0x0A, 0x75, 0x55, 0xC8,
    0x37, 0x2A, 0xC5, 0x5E, 0x81, 0x4A, 0xE2, 0x15, 0x13, 0xAC, 0xEB, 0x2E, 0xBC, 0xDE, 0xD7, 0xF5,
    0xE6, 0xBA, 0x7D, 0x25, 0x98, 0x69, 0x73, 0x5B, 0xBE, 0xE7, 0x32, 0xA9, 0x09, 0x19, 0xF0, 0x44,
};

uint8_t inv_sbox[256] = {
    0x59, 0x8A, 0x2C, 0x1D, 0xD8, 0xC3, 0xA2, 0xAF, 0x5C, 0xFC, 0xDC, 0x7A, 0x49, 0xBE, 0x93, 0xCB,
    0x90, 0xD9, 0x36, 0xE8, 0x64, 0xE7, 0x4B, 0x85, 0x46, 0xFD, 0x81, 0xAC, 0x42, 0x02, 0x79, 0x62,
    0x00, 0x3E, 0x04, 0xB1, 0x25, 0xF3, 0x1C, 0xBA, 0x2E, 0xAA, 0xE1, 0x0C, 0x14, 0x56, 0xEB, 0x40,
    0x35, 0x28, 0xFA, 0x8E, 0xB3, 0xD5, 0x55, 0xE0, 0x74, 0x01, 0x9D, 0x6D, 0xAE, 0x3B, 0x15, 0x7B,
    0xCF, 0x4F, 0x5A, 0x3C, 0xFF, 0xA7, 0xC9, 0x82, 0x0D, 0xB2, 0xE5, 0xB0, 0x20, 0xA5, 0x0F, 0x34,
    0x99, 0x4D, 0x43, 0x95, 0xAB, 0xDE, 0x0E, 0x9F, 0xC2, 0xC6, 0x39, 0xF7, 0x84, 0x5E, 0xE3, 0x2A,
    0x68, 0x24, 0xDA, 0x3A, 0xBC, 0x58, 0xC4, 0xB6, 0x7D, 0xF5, 0x9E, 0xD4, 0x69, 0xCC, 0x83, 0x54,
    0x05, 0xB8, 0x65, 0xF6, 0xA9, 0xDD, 0x88, 0x63, 0x50, 0x32, 0xB4, 0x2B, 0x75, 0xF2, 0xD6, 0x29,
    0x7E, 0xE4, 0x47, 0x17, 0x92, 0xDB, 0x2F, 0x96, 0xB5, 0x22, 0x30, 0x33, 0x23, 0xD2, 0x91, 0xA6,
    0x08, 0x51, 0xCE, 0x89, 0xB9, 0x9A, 0x5B, 0x8B, 0xF4, 0x1B, 0x13, 0x48, 0x72, 0x71, 0x37, 0x6F,
    0x16, 0x07, 0x03, 0x8C, 0x26, 0x5D, 0x10, 0xCA, 0x70, 0xFB, 0x5F, 0x52, 0xE9, 0x6B, 0x60, 0x7C,
    0x06, 0x86, 0x18, 0x87, 0x73, 0x1A, 0xA3, 0x66, 0x78, 0x97, 0xF1, 0x53, 0xEC, 0x1E, 0xF8, 0x6E,
    0x94, 0x3F, 0x21, 0x0B, 0x61, 0xE2, 0x6A, 0xD0, 0xDF, 0xBF, 0xBD, 0x7F, 0x27, 0x6C, 0x44, 0xD3,
    0x57, 0x12, 0x11, 0xA0, 0xCD, 0x80, 0x77, 0xEE, 0xC1, 0x8F, 0xAD, 0x3D, 0x4C, 0x4A, 0xED, 0x45,
    0xC7, 0xC8, 0xE6, 0xC0, 0xC5, 0xA8, 0xF0, 0xF9, 0xBB, 0xD1, 0x1F, 0xEA, 0x9C, 0x98, 0x09, 0xA4,
    0xFE, 0x38, 0x41, 0x8D, 0x0A, 0xEF, 0x4E, 0x19, 0xA1, 0x2D, 0xD7, 0xB7, 0x67, 0x31, 0x76, 0x9B,
};



// 初始密钥
uint8_t master_key[BLOCK_SIZE] = {
    0x2B, 0xEC, 0xC3, 0x54, 0xA5, 0x21, 0x18, 0x98, 0xB9, 0xCB, 0xE6, 0x68, 0xED, 0xC1, 0x84, 0x05,
    0x86, 0xE5, 0x91, 0x37, 0x74, 0xB3, 0x59, 0xC7, 0x63, 0x03, 0x53, 0x69, 0x8E, 0xFF, 0xC9, 0x41,
    0x4F, 0x45, 0xA9, 0x3D, 0xCE, 0x48, 0xA3, 0x35, 0x20, 0xE3, 0x16, 0xFE, 0xDB, 0x0C, 0xA6, 0x90,
    0x7E, 0x00, 0x7D, 0x99, 0x76, 0x60, 0x7F, 0x66, 0x8F, 0x0E, 0x2F, 0x46, 0x19, 0xB8, 0xAF, 0x55,
    0x95, 0x3C, 0xB5, 0x5D, 0x28, 0x93, 0x0F, 0x8B, 0x01, 0x1B, 0x44, 0x47, 0x40, 0x17, 0x70, 0xB4,
    0x9C, 0x6D, 0x79, 0x1F, 0x82, 0xEE, 0x5B, 0xA4, 0x4D, 0x72, 0x92, 0x97, 0x87, 0xDC, 0xF0, 0x5E,
    0xDA, 0xD4, 0xD5, 0xF5, 0x06, 0xCA, 0x89, 0x6B, 0xD8, 0xC5, 0xE7, 0xE8, 0x32, 0x77, 0x0B, 0xFC,
    0x50, 0xE0, 0x71, 0xC0, 0x73, 0xC6, 0xA0, 0xF4, 0x58, 0x7C, 0x23, 0xF2, 0x24, 0xF7, 0xD1, 0x78,
    0xEF, 0xBD, 0x5C, 0xBF, 0xBE, 0x3B, 0x33, 0x5A, 0x67, 0xD2, 0x52, 0x39, 0x31, 0xF6, 0xF9, 0x81,
    0x22, 0xDF, 0x57, 0x4A, 0x3F, 0xA1, 0xD3, 0x6A, 0xAD, 0x9A, 0x1C, 0x1D, 0x43, 0x85, 0x12, 0x2E,
    0x88, 0x34, 0x2A, 0xC4, 0x0D, 0x2C, 0x13, 0x1E, 0xBC, 0x36, 0x9D, 0x0A, 0xEB, 0xDE, 0xF8, 0x15,
    0xD9, 0xC8, 0x61, 0xD7, 0x30, 0x9F, 0x8C, 0x08, 0xAC, 0xB7, 0xCC, 0x4B, 0x1A, 0x6E, 0x29, 0x80,
    0xB0, 0x5F, 0x6C, 0x27, 0x7B, 0x14, 0x49, 0xE9, 0xDD, 0xAA, 0x09, 0xAB, 0xD6, 0xA7, 0x2D, 0xB1,
    0x8D, 0x42, 0x4C, 0x04, 0xCD, 0x6F, 0x02, 0xE2, 0xF3, 0xAE, 0x7A, 0x9B, 0xB2, 0xA2, 0xBA, 0x38,
    0x83, 0xD0, 0xBB, 0x51, 0x25, 0xF1, 0x11, 0x8A, 0xFB, 0x07, 0xFA, 0x3A, 0x96, 0x4E, 0x3E, 0x94,
    0x56, 0xE4, 0x10, 0xE1, 0x62, 0xEA, 0xCF, 0xFD, 0x9E, 0xC2, 0x65, 0x64, 0x26, 0x75, 0xB6, 0xA8,
};

// 生成每一轮的 round key（简单示例：每轮 key = key[i] ^ round_number）
void GenerateRoundKey(uint8_t* round_key, int round) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        round_key[i] = master_key[i] ^ (round * 0x11);
    }
}

// SubBytes
void SubBytes(uint8_t* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

// ShiftRows（标准样式）
void ShiftRows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];

    // 每一行分别左移
    for (int i = 0; i < 64; i++) {
        temp[i] = state[i];  // 第一行
    }

    // 第二行左移一个位置
    for (int i = 0; i < 64; i++) {
        temp[64 + i] = state[64 + (i + 1) % 64];
    }

    // 第三行左移两个位置
    for (int i = 0; i < 64; i++) {
        temp[128 + i] = state[128 + (i + 2) % 64];
    }

    // 第四行左移三个位置
    for (int i = 0; i < 64; i++) {
        temp[192 + i] = state[192 + (i + 3) % 64];
    }

    memcpy(state, temp, BLOCK_SIZE);
}

// 魔改 MixColumns：XOR 每列 + 循环左移
void MixColumns(uint8_t* state) {
    for (int col = 0; col < 64; ++col) {
        int base = col * 4;
        uint8_t a = state[base];
        uint8_t b = state[base + 1];
        uint8_t c = state[base + 2];
        uint8_t d = state[base + 3];

        state[base] = a ^ b;
        state[base + 1] = b ^ c;
        state[base + 2] = c ^ d;
        state[base + 3] = (d << 1) | (d >> 7); // 左移1位，带循环
    }
}

// AddRoundKey
void AddRoundKey(uint8_t* state, uint8_t* round_key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] ^= round_key[i];
    }
}

// 主加密函数
void EncryptBlock(uint8_t* input, uint8_t* output) {
    uint8_t state[BLOCK_SIZE];
    memcpy(state, input, BLOCK_SIZE);

    for (int round = 0; round < ROUNDS; round++) {
        uint8_t round_key[BLOCK_SIZE];
        GenerateRoundKey(round_key, round);
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round_key);
    }

    memcpy(output, state, BLOCK_SIZE);
}


void InvSubBytes(uint8_t* state) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

void InvShiftRows(uint8_t* state) {
    uint8_t temp[BLOCK_SIZE];

    // 第一行不变
    for (int i = 0; i < 64; i++) {
        temp[i] = state[i];
    }

    // 第二行右移一个位置
    for (int i = 0; i < 64; i++) {
        temp[64 + i] = state[64 + (i - 1 + 64) % 64];
    }

    // 第三行右移两个位置
    for (int i = 0; i < 64; i++) {
        temp[128 + i] = state[128 + (i - 2 + 64) % 64];
    }

    // 第四行右移三个位置
    for (int i = 0; i < 64; i++) {
        temp[192 + i] = state[192 + (i - 3 + 64) % 64];
    }

    memcpy(state, temp, BLOCK_SIZE);
}

// 魔改 MixColumns 的逆运算：手动还原每列
void InvMixColumns(uint8_t* state) {
    for (int col = 0; col < 64; ++col) {
        int base = col * 4;
        uint8_t s0 = state[base];
        uint8_t s1 = state[base + 1];
        uint8_t s2 = state[base + 2];
        uint8_t s3 = state[base + 3];

        // 解密过程为原始逆运算（从解密函数推导出公式）
        uint8_t d = (s3 >> 1) | (s3 << 7); // 逆向循环左移
        uint8_t c = s2 ^ d;
        uint8_t b = s1 ^ c;
        uint8_t a = s0 ^ b;

        state[base] = a;
        state[base + 1] = b;
        state[base + 2] = c;
        state[base + 3] = d;
    }
}

void DecryptBlock(uint8_t* input, uint8_t* output) {
    uint8_t state[BLOCK_SIZE];
    memcpy(state, input, BLOCK_SIZE);

    for (int round = ROUNDS - 1; round >= 0; round--) {
        uint8_t round_key[BLOCK_SIZE];
        GenerateRoundKey(round_key, round);
        AddRoundKey(state, round_key);
        InvMixColumns(state);
        InvShiftRows(state);
        InvSubBytes(state);
    }

    memcpy(output, state, BLOCK_SIZE);
}




int main() {
    // 初始化 OpenSSL 3.0
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS
        | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    // 生成密钥对
    EVP_PKEY_ptr keyPair = generateRSAKeyPair();
    std::cout << "已生成 RSA-2048 密钥对\n";

    // 保存密钥
    saveKeyToFile(keyPair.get(), "private_key.pem", true);
    saveKeyToFile(keyPair.get(), "public_key.pem", false);
    std::cout << "密钥已保存到文件\n";

	std::cout << "\n私钥: \n";
	printKey(keyPair.get(), true);
	std::cout << "\n公钥: \n";
	printKey(keyPair.get(), false);

    // 要签名的消息
    const char* message = "Welcome";
    std::cout << "\n原始消息: " << message << std::endl;
    std::vector<unsigned char> signature = signMessage(message, keyPair.get());
    std::cout << "\n签名原始结果: ";
    printHex(signature);
	saveSigToFile(signature, "raw_key1.bin");


    uint8_t ciphertext[BLOCK_SIZE];
    // 修改 EncryptBlock 调用，将 std::vector 转换为 uint8_t*  
    EncryptBlock(signature.data(), ciphertext);
    std::cout << "\n签名加密结果: ";
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
	saveAESToFile(ciphertext, "key1.bin",BLOCK_SIZE);

    uint8_t newplaintext[BLOCK_SIZE];
    DecryptBlock(ciphertext, newplaintext);
    std::cout << "\n签名解密结果: ";
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        printf("%02x", newplaintext[i]);
    }
    printf("\n");


    message = "Here is the key";
    std::cout << "\n原始消息: " << message << std::endl;
    signature = signMessage(message, keyPair.get());
    std::cout << "\n签名原始结果: ";
    printHex(signature);
    saveSigToFile(signature, "raw_key2.bin");

    EncryptBlock(signature.data(), ciphertext);
    std::cout << "\n签名加密结果: ";
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    saveAESToFile(ciphertext, "key2.bin", BLOCK_SIZE);
    DecryptBlock(ciphertext, newplaintext);
    std::cout << "\n签名解密结果: ";
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        printf("%02x", newplaintext[i]);
    }
    printf("\n");

    // 验证
    bool isValid = verifySignature(message, signature, keyPair.get());
    std::cout << "\n验证结果: " << (isValid ? "有效" : "无效") << std::endl;

    // 测试篡改消息
    std::string tampered = "这是一条被篡改的消息";
    bool isTamperedValid = verifySignature(tampered, signature, keyPair.get());
    std::cout << "篡改后验证: " << (isTamperedValid ? "有效" : "无效") << std::endl;

    // 从文件加载验证
    EVP_PKEY_ptr pubKey = loadKeyFromFile("public_key.pem", false);
    isValid = verifySignature(message, signature, pubKey.get());
    std::cout << "从文件加载公钥验证: " << (isValid ? "有效" : "无效") << std::endl;

    // 清理
    EVP_cleanup();
    return 0;
}