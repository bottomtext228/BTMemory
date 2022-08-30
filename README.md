# BTMemory
Memory library ( patches, NOPs )

```cpp
CPatch* BTMemory::Patch(uintptr_t destination, const void* patchBytes, size_t patchSize, bool isSimple = false)
```
```cpp
CPatch* BTMemory::Nop(uintptr_t destination, size_t patchSize, bool isSimple = false)
```
```cpp
void BTMemory::CPatch::ApplyPatch();
```
```cpp
void BTMemory::CPatch::RestorePatch();
```
```cpp
void BTMemory::CPatch::DestroyPatch();
```

# Example:
```cpp
// Assault Cube no recoil
DWORD WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		static BTMemory::CPatch* noRecoilNop = BTMemory::Nop((DWORD)GetModuleHandle(NULL) + 0x63786, 10); // nop the function call
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
