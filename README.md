# BTMemory
Memory library ( patches, NOPs )
# 

```cpp
uintptr_t FindSignature(const char* moduleName, const void* signatureString, const char* mask);
```
```cpp
uintptr_t FindDMAAddy(uintptr_t baseAddress, std::vector<unsigned int> offsets);
```
```cpp
void UnpatchAll();
```


# BTMemory::Patcher
```cpp
CPatch* BTMemory::Patcher::Patch(uintptr_t destination, const void* patchBytes, size_t patchSize, bool isSimple = false);
```
```cpp
CPatch* BTMemory::Patcher::Nop(uintptr_t destination, size_t patchSize, bool isSimple = false);
```
```cpp
void BTMemory::Patcher::CPatch::ApplyPatch();
```
```cpp
void BTMemory::Patcher::CPatch::RestorePatch();
```
```cpp
void BTMemory::Patcher::CPatch::DestroyPatch();
```

# BTMemory::VMTHooker 
```cpp
BTMemory::VMTHooker::CVMTHook* BTMemory::VMTHooker::Hook(void *pVMT, int iMethodIndex, void *fnHook);
```
```cpp
void *BTMemory::VMTHooker::CVMTHook::ApplyHook()
```
```cpp
void *BTMemory::VMTHooker::CVMTHook::DestroyHook();
```
```cpp
int BTMemory::VMTHooker::CVMTHook::GetMethodsCount();
```

# Example:
```cpp
#include "BTMemory.h"


// Assault Cube no recoil
DWORD WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		static auto* noRecoilNop = BTMemory::Patcher::Nop((DWORD)GetModuleHandle(NULL) + 0x63786, 10); // nop the function call
		// or
		//static BTMemory::CPatch* noRecoilPatch = BTMemory::Patch((DWORD)GetModuleHandle(NULL) + 0x62020, "\xC2\x80\x00", 3); // "ret 08" to prevent execution of function
		noRecoilNop->ApplyPatch();

	
		break;
	case DLL_PROCESS_DETACH:
		BTMemory::UnpatchAll(); // restore original bytes and deletes allocated memory for them
		break;
	}
	return TRUE;
}
```
Other examples at `main.cpp`
