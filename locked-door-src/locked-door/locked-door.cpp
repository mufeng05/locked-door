#include <cstdio>
#include <cstring>
#include <cmath>
//#include <openssl/evp.h>
#include <openssl/pem.h>
//#include <memory.h>
//#include <crtdefs.h>
//#include <openssl/core_names.h>
//#include <openssl/applink.c>

static void HandleErrors()
{
	abort();
}

void* function_address = (void*)EVP_DigestVerifyFinal;

unsigned char expected_hash[32] = {
	0xc2, 0x6d, 0x46, 0x99, 0xab, 0xaf, 0x67, 0xee,
	0x91, 0x00, 0x2a, 0xca, 0x6e, 0x07, 0xec, 0xcd,
	0x29, 0x8c, 0xd0, 0x2a, 0xe3, 0xb9, 0x63, 0xbd,
	0x01, 0xb3, 0x63, 0x45, 0x7c, 0x93, 0x43, 0xf8
};

constexpr size_t PUBKEY_LEN = 450;
constexpr size_t FLAG_LEN = 20;
constexpr size_t SIG_LEN = 256;
constexpr int ROUNDS = 14;

constexpr float PUBKEY_FLOATS[PUBKEY_LEN] = { 
	0.174877f, 0.174877f, 0.174877f, 0.174877f, 0.174877f,
	0.254966f, 0.266280f, 0.273802f, 0.281307f, 0.299995f,
	0.124675f, 0.307439f, 0.325964f, 0.254966f, 0.292533f,
	0.281307f, 0.258741f, 0.124675f, 0.288796f, 0.266280f,
	0.340695f, 0.174877f, 0.174877f, 0.174877f, 0.174877f,
	0.174877f, 0.039053f, 0.296266f, 0.281307f, 0.281307f,
	0.254966f, 0.281307f, 0.402332f, 0.251187f, 0.299995f,
	0.254966f, 0.391576f, 0.405905f, 0.427211f, 0.395167f,
	0.405905f, 0.398753f, 0.273802f, 0.220821f, 0.448283f,
	0.186403f, 0.254966f, 0.251187f, 0.311153f, 0.266280f,
	0.270043f, 0.251187f, 0.251187f, 0.303719f, 0.258741f,
	0.251187f, 0.311153f, 0.217010f, 0.251187f, 0.296266f,
	0.281307f, 0.281307f, 0.254966f, 0.258741f, 0.391576f,
	0.288796f, 0.258741f, 0.251187f, 0.311153f, 0.266280f,
	0.251187f, 0.220821f, 0.380766f, 0.182564f, 0.186403f,
	0.437777f, 0.322269f, 0.340695f, 0.329654f, 0.307439f,
	0.311153f, 0.285054f, 0.391576f, 0.387979f, 0.413032f,
	0.458727f, 0.333340f, 0.455253f, 0.311153f, 0.314863f,
	0.416587f, 0.039053f, 0.405905f, 0.441286f, 0.344365f,
	0.296266f, 0.420135f, 0.413032f, 0.413032f, 0.194073f,
	0.167180f, 0.402332f, 0.288796f, 0.266280f, 0.398753f,
	0.217010f, 0.413032f, 0.270043f, 0.398753f, 0.314863f,
	0.281307f, 0.420135f, 0.314863f, 0.292533f, 0.458727f,
	0.307439f, 0.182564f, 0.209377f, 0.380766f, 0.369905f,
	0.303719f, 0.251187f, 0.377152f, 0.344365f, 0.213195f,
	0.325964f, 0.398753f, 0.423676f, 0.299995f, 0.377152f,
	0.296266f, 0.322269f, 0.251187f, 0.167180f, 0.373531f,
	0.398753f, 0.398753f, 0.220821f, 0.254966f, 0.322269f,
	0.427211f, 0.387979f, 0.437777f, 0.322269f, 0.427211f,
	0.344365f, 0.413032f, 0.292533f, 0.430740f, 0.369905f,
	0.277557f, 0.251187f, 0.220821f, 0.270043f, 0.314863f,
	0.213195f, 0.039053f, 0.201731f, 0.213195f, 0.344365f,
	0.416587f, 0.273802f, 0.416587f, 0.311153f, 0.266280f,
	0.213195f, 0.288796f, 0.398753f, 0.413032f, 0.314863f,
	0.281307f, 0.402332f, 0.167180f, 0.427211f, 0.197904f,
	0.205555f, 0.387979f, 0.395167f, 0.329654f, 0.258741f,
	0.337020f, 0.329654f, 0.318568f, 0.194073f, 0.395167f,
	0.416587f, 0.369905f, 0.194073f, 0.303719f, 0.340695f,
	0.405905f, 0.423676f, 0.288796f, 0.444788f, 0.455253f,
	0.296266f, 0.325964f, 0.391576f, 0.209377f, 0.387979f,
	0.377152f, 0.337020f, 0.441286f, 0.254966f, 0.311153f,
	0.194073f, 0.437777f, 0.314863f, 0.333340f, 0.402332f,
	0.322269f, 0.182564f, 0.186403f, 0.167180f, 0.186403f,
	0.455253f, 0.186403f, 0.448283f, 0.190240f, 0.451771f,
	0.314863f, 0.039053f, 0.254966f, 0.270043f, 0.325964f,
	0.377152f, 0.391576f, 0.273802f, 0.458727f, 0.220821f,
	0.314863f, 0.262512f, 0.285054f, 0.430740f, 0.437777f,
	0.322269f, 0.311153f, 0.258741f, 0.182564f, 0.201731f,
	0.314863f, 0.387979f, 0.220821f, 0.201731f, 0.281307f,
	0.416587f, 0.220821f, 0.205555f, 0.344365f, 0.377152f,
	0.391576f, 0.391576f, 0.311153f, 0.409472f, 0.285054f,
	0.441286f, 0.318568f, 0.420135f, 0.254966f, 0.444788f,
	0.270043f, 0.420135f, 0.307439f, 0.448283f, 0.434262f,
	0.167180f, 0.337020f, 0.182564f, 0.380766f, 0.277557f,
	0.197904f, 0.194073f, 0.344365f, 0.409472f, 0.398753f,
	0.427211f, 0.201731f, 0.402332f, 0.303719f, 0.251187f,
	0.387979f, 0.167180f, 0.296266f, 0.448283f, 0.190240f,
	0.387979f, 0.039053f, 0.197904f, 0.373531f, 0.281307f,
	0.307439f, 0.299995f, 0.413032f, 0.384375f, 0.213195f,
	0.373531f, 0.266280f, 0.197904f, 0.416587f, 0.201731f,
	0.213195f, 0.205555f, 0.285054f, 0.413032f, 0.337020f,
	0.194073f, 0.303719f, 0.437777f, 0.292533f, 0.409472f,
	0.409472f, 0.197904f, 0.437777f, 0.303719f, 0.277557f,
	0.455253f, 0.277557f, 0.333340f, 0.377152f, 0.288796f,
	0.437777f, 0.402332f, 0.380766f, 0.258741f, 0.391576f,
	0.340695f, 0.391576f, 0.337020f, 0.427211f, 0.387979f,
	0.333340f, 0.307439f, 0.384375f, 0.434262f, 0.455253f,
	0.416587f, 0.201731f, 0.270043f, 0.430740f, 0.254966f,
	0.190240f, 0.197904f, 0.373531f, 0.277557f, 0.285054f,
	0.201731f, 0.205555f, 0.322269f, 0.398753f, 0.281307f,
	0.391576f, 0.039053f, 0.209377f, 0.322269f, 0.303719f,
	0.455253f, 0.322269f, 0.311153f, 0.380766f, 0.318568f,
	0.186403f, 0.409472f, 0.277557f, 0.373531f, 0.209377f,
	0.182564f, 0.209377f, 0.416587f, 0.167180f, 0.258741f,
	0.416587f, 0.194073f, 0.420135f, 0.387979f, 0.448283f,
	0.303719f, 0.434262f, 0.285054f, 0.451771f, 0.186403f,
	0.213195f, 0.420135f, 0.380766f, 0.391576f, 0.314863f,
	0.391576f, 0.270043f, 0.380766f, 0.369905f, 0.318568f,
	0.197904f, 0.409472f, 0.387979f, 0.318568f, 0.387979f,
	0.273802f, 0.288796f, 0.197904f, 0.325964f, 0.288796f,
	0.441286f, 0.384375f, 0.329654f, 0.391576f, 0.182564f,
	0.441286f, 0.318568f, 0.444788f, 0.303719f, 0.384375f,
	0.434262f, 0.190240f, 0.405905f, 0.333340f, 0.262512f,
	0.307439f, 0.039053f, 0.314863f, 0.311153f, 0.281307f,
	0.262512f, 0.251187f, 0.311153f, 0.251187f, 0.254966f,
	0.039053f, 0.174877f, 0.174877f, 0.174877f, 0.174877f,
	0.174877f, 0.266280f, 0.299995f, 0.262512f, 0.124675f,
	0.307439f, 0.325964f, 0.254966f, 0.292533f, 0.281307f,
	0.258741f, 0.124675f, 0.288796f, 0.266280f, 0.340695f,
	0.174877f, 0.174877f, 0.174877f, 0.174877f, 0.174877f };

constexpr float FLAG_FLOATS[FLAG_LEN] = { // Y0u_0p3n_7h3_d00r!!!
	0.340695f, 0.186403f, 0.441286f, 0.362635f, 0.186403f,
	0.423676f, 0.197904f, 0.416587f, 0.362635f, 0.213195f,
	0.395167f, 0.197904f, 0.362635f, 0.380766f, 0.186403f,
	0.186403f, 0.430740f, 0.128550f, 0.128550f, 0.128550f };

constexpr uint8_t INV_SBOX[256] = {
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

constexpr uint8_t MASTER_KEY[SIG_LEN] = {
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

static void ConvertFloatsToChars(const float* floats, char* result, size_t length)
{
	for (size_t i = 0; i < length; ++i)
	{
		long long val = llround(asinf(floats[i]) * 256.0);
		result[i] = static_cast<char>(val);
	}
	result[length] = '\0';
}

static void PrintFlag()
{
	char flag_array[FLAG_LEN];
	ConvertFloatsToChars(FLAG_FLOATS, flag_array, FLAG_LEN);
	printf("flag{%s}\n", flag_array);
	return;
}

static void VerifySignature2(const char* message,
	const unsigned char* signature,
	size_t SIG_LEN,
	EVP_PKEY* pkey)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

	if (!ctx)
		HandleErrors();

	if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
	{
		HandleErrors();
	}

	if (EVP_DigestVerifyUpdate(ctx, message, strlen(message)) <= 0)
	{
		HandleErrors();
	}

	unsigned char current_hash[EVP_MAX_MD_SIZE];
	unsigned int current_hash_len = 0;
	EVP_Digest((unsigned char*)function_address, 4, current_hash, &current_hash_len, EVP_sha256(), NULL);
	if (memcmp(expected_hash, current_hash, current_hash_len) != 0)
	{
		printf("File corrupted! This program has been manipulated and maybe it's infected by a Virus or cracked. This file won't work anymore.\n");
		HandleErrors();
	}

	int ret = EVP_DigestVerifyFinal(ctx, signature, SIG_LEN);
	EVP_MD_CTX_free(ctx);

	if (ret == 0)
	{
		printf("The key2 is wrong\n");
	}
	else if (ret == 1)
	{
		printf("The key2 is correct, here is your flag\n");
		PrintFlag();
	}
	else if (ret < 0)
	{
		HandleErrors();
	}
	return;
}

static bool VerifySignature1(const char* message,
	const unsigned char* signature,
	size_t SIG_LEN,
	EVP_PKEY* pkey)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();

	if (!ctx)
		HandleErrors();

	if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
	{
		HandleErrors();
	}

	if (EVP_DigestVerifyUpdate(ctx, message, strlen(message)) <= 0)
	{
		HandleErrors();
	}

	unsigned char current_hash[EVP_MAX_MD_SIZE];
	unsigned int current_hash_len = 0;
	EVP_Digest((unsigned char*)function_address, 4, current_hash, &current_hash_len, EVP_sha256(), NULL);
	if (memcmp(expected_hash, current_hash, current_hash_len) != 0)
	{
		printf("File corrupted! This program has been manipulated and maybe it's infected by a Virus or cracked. This file won't work anymore.\n");
		HandleErrors();
	}

	int ret = EVP_DigestVerifyFinal(ctx, signature, SIG_LEN);
	EVP_MD_CTX_free(ctx);

	if (ret < 0) HandleErrors();

	return ret == 1;
}

static EVP_PKEY* LoadPubkey(const char* pubkey)
{
	EVP_PKEY* pkey = nullptr;
	BIO* bio = BIO_new_mem_buf((void*)pubkey, -1);
	if (!bio)
		HandleErrors();
	pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!pkey)
		HandleErrors();
	return pkey;
}

static unsigned char* ReadSignatureFromFile(const char* filename, size_t SIG_LEN)
{
	FILE* file = fopen(filename, "rb");
	if (!file)
	{
		printf("Key not found\n");
		HandleErrors();
	}
	else {
		unsigned char* signature = (unsigned char*)malloc(SIG_LEN);
		if (!signature)
		{
			fclose(file);
			HandleErrors();
		}
		else {
			if (fread(signature, sizeof(unsigned char), SIG_LEN, file) != SIG_LEN)
			{
				free(signature);
				fclose(file);
				HandleErrors();
			}
			else {
				fclose(file);
				return signature;
			}
		}
	}
}

static void DecryptBlock(uint8_t* input, uint8_t* output) {
	uint8_t state[SIG_LEN];
	memcpy(state, input, SIG_LEN);

	for (int round = ROUNDS - 1; round >= 0; round--) {
		// 生成轮密钥
		uint8_t round_key[SIG_LEN]{};
		for (int i = 0; i < SIG_LEN; i++) {
			round_key[i] = MASTER_KEY[i] ^ (round * 0x11);
		}

		// AddRoundKey
		for (int i = 0; i < SIG_LEN; i++) {
			state[i] ^= round_key[i];
		}

		// InvMixColumns
		for (int col = 0; col < 64; ++col) {
			int base = col * 4;
			uint8_t s0 = state[base];
			uint8_t s1 = state[base + 1];
			uint8_t s2 = state[base + 2];
			uint8_t s3 = state[base + 3];

			uint8_t d = (s3 >> 1) | (s3 << 7); // 逆向循环左移
			uint8_t c = s2 ^ d;
			uint8_t b = s1 ^ c;
			uint8_t a = s0 ^ b;

			state[base] = a;
			state[base + 1] = b;
			state[base + 2] = c;
			state[base + 3] = d;
		}

		// InvShiftRows
		uint8_t temp[SIG_LEN]{};
		for (int i = 0; i < 64; i++) {
			temp[i] = state[i];
		}
		for (int i = 0; i < 64; i++) {
			temp[64 + i] = state[64 + (i - 1 + 64) % 64];
		}
		for (int i = 0; i < 64; i++) {
			temp[128 + i] = state[128 + (i - 2 + 64) % 64];
		}
		for (int i = 0; i < 64; i++) {
			temp[192 + i] = state[192 + (i - 3 + 64) % 64];
		}
		memcpy(state, temp, SIG_LEN);

		// InvSubBytes
		for (int i = 0; i < SIG_LEN; i++) {
			state[i] = INV_SBOX[state[i]];
		}
	}

	memcpy(output, state, SIG_LEN);
}

int main()
{
	const char* file_name1 = "key1.bin";
	const char* file_name2 = "key2.bin";
	const char* message1 = "Welcome";
	const char* message2 = "Here is the key";

	printf("Flag is behind the door\n");

	char pub_array[PUBKEY_LEN];
	ConvertFloatsToChars(PUBKEY_FLOATS, pub_array, PUBKEY_LEN);
	EVP_PKEY* pubkey = LoadPubkey(pub_array);

	unsigned char* read_signature = ReadSignatureFromFile(file_name1, SIG_LEN);
	uint8_t plain_signature[SIG_LEN];
	DecryptBlock(read_signature, plain_signature);

	if (VerifySignature1(message1, plain_signature, SIG_LEN, pubkey))
	{
		printf("The key1 is correct, but there is a second door\n");

		char* pub_array_clone = new char[PUBKEY_LEN + 1];

		memcpy(pub_array_clone, pub_array, PUBKEY_LEN);
		pub_array_clone[PUBKEY_LEN] = '\0';
		EVP_PKEY* pubkey_clone = LoadPubkey(pub_array_clone);

		read_signature = ReadSignatureFromFile(file_name2, SIG_LEN);

		DecryptBlock(read_signature, plain_signature);

		VerifySignature2(message2, plain_signature, SIG_LEN, pubkey_clone);
	}
	else
	{
		printf("The key1 is wrong\n");
	}

	free(read_signature);

	return 0;
}