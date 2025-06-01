// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include <MinHook.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <wininet.h>
#include <shlobj.h>
#include <wchar.h>
#include <intrin.h>

typedef int8_t   int8;
typedef int16_t  int16;
typedef int32_t  int32;
typedef int64_t  int64;
typedef uint8_t  uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef LPVOID(*api_MemCpy)(LPVOID, LPCVOID, SIZE_T);
static api_MemCpy orig_MemCpy;
static api_MemCpy func_MemCpy;

const size_t PUBKEYLEN = 450;

const char* NEWPUBKEY = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtVwM8eBuDAjwCCOhrRg
iSMGs1sxd41ZFsB7doOtIV5mqaUp8CAJuP543cJ2VfVO6C8yel1+5xP8jLCVZcMA
94wMnymUmkmj+2VcrOFifhGSKZqmwMvxI4z8j7/kD2+A7Hfx/g3f7triH44pfk/R
Qgfz0/Syrr/ak10ibKJpNZaN+x9I0kWloWdbDXoYlQusE8L/Ouaep/q3dMRPLf3F
xHSQdgBBq4VBMNX+GWX+SwG5gFzCQfv5cxfP1Onsq4vr2mQbnLC5CmlQOSB8Gj4U
ameBnJvpRC15nWhm0jhSnYuinmM64s9poX027nto159nzgBfBFMs7YAB/G+2Ad3b
JQIDAQAB
-----END PUBLIC KEY-----)";

// 我们的钩子函数
static LPVOID hook_MemCpy(LPVOID dst, LPCVOID src, SIZE_T len) {

	uint8* dst_ = static_cast<uint8*>(dst);
	const uint8* src_ = static_cast<const uint8*>(src);
	const uint32* u = static_cast<const uint32*>(src);

	if (len == PUBKEYLEN && (u[0] == 0x2d2d2d2d && u[1] == 0x4745422d && u[2] == 0x50204e49 && u[3] == 0x494c4255)) {
		// 这里可以添加你想要的操作
		// 例如，打印源和目标地址
		printf("hook memcpy: dst: %p, src: %p, len: %zu\n", dst_, src_, len);
		//printf("hook memcpy: u[0]: %x, u[1]: %x, u[2]: %x, u[3]: %x\n", u[0], u[1], u[2], u[3]);
		printf("src: %s\n", static_cast<const char*>(src));
		printf("newpubkey length: %zu\n", strlen(NEWPUBKEY));
		src = NEWPUBKEY;
		printf("newsrc: %s\n", static_cast<const char*>(src));
	}

	return memcpy(dst, src, len);
}

static bool initMemCpyHook() {
	// 获取 memcpy 地址
	// 修复 func_MemCpy 的赋值问题，确保类型匹配  
	// 修复 E0852 错误：确保 base 是一个指向完整对象类型的指针  
	HANDLE proc = GetCurrentProcess();
	HMODULE base = GetModuleHandleW(NULL); // 将 LPVOID 替换为 HMODULE  
	LPVOID f = reinterpret_cast<LPBYTE>(base) + 0x002A7910; // 使用 LPBYTE 进行指针运算  
	printf("base: %p\n", base);
	printf("f: %p\n", f);
	func_MemCpy = reinterpret_cast<api_MemCpy>(f);

	// 创建钩子
	if (MH_CreateHook(f, &hook_MemCpy, (LPVOID*)&orig_MemCpy) != MH_OK) {
		printf("Hook memcpy creation failed\n");
		return FALSE;
	}

	// 启用钩子
	if (MH_EnableHook(f) != MH_OK) {
		printf("Hook memcpy enable failed\n");
		return FALSE;
	}

	printf("Memcpy hook installed successfully\n");
	return TRUE;
}

// 安装钩子
static BOOL InstallHook() {
	if (MH_Initialize() != MH_OK) {
		printf("MinHook initialization failed\n");
		return FALSE;
	}

	if (!initMemCpyHook()) {
		printf("Failed to initialize memcpy hook\n");
	}

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		printf("Hook enable failed\n");
		return FALSE;
	}

	printf("Hook installed successfully\n");
	return TRUE;
}

// 移除钩子
static BOOL RemoveHook() {
	if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK) {
		printf("Hook disable failed\n");
		return FALSE;
	}

	if (MH_Uninitialize() != MH_OK) {
		printf("MinHook uninitialization failed\n");
		return FALSE;
	}

	printf("Memcpy hook removed successfully\n");
	return TRUE;
}

static BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//DisableThreadLibraryCalls(hModule);
		InstallHook();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		RemoveHook();
		break;
	}
	return TRUE;
}

