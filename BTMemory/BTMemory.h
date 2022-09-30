#pragma once
#include <Windows.h>
#include <vector>
#include <psapi.h>

#define k_page_writeable (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
#define k_page_readable (k_page_writeable|PAGE_READONLY|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_WRITECOPY)
#define k_page_offlimits (PAGE_GUARD|PAGE_NOACCESS)


/* TODO:
*  JMP/Call hooker :irony:
*/
namespace BTMemory {
	namespace VMTHooker {
		class CVMTHook {
			void* m_pOriginalVMT;
			void** m_pVMT;
			int m_iMethodsCount;
			int m_iHookedMethod;
			void* m_fnHookFunction;
			static std::vector<CVMTHook*> pVMTHooks;

		public:
			int GetMethodsCount() {
				int methodsCount = 0;

				while (CanReadPointer(m_pVMT[methodsCount])) {
					methodsCount++;
				}
				return methodsCount;
			}


			void* ApplyHook() {
				void* oldMethod = m_pVMT[m_iHookedMethod];
				DWORD oldProtect;
				VirtualProtect(m_pVMT, m_iMethodsCount * sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
				m_pVMT[m_iHookedMethod] = m_fnHookFunction;
				VirtualProtect(m_pVMT, m_iMethodsCount * sizeof(uintptr_t), oldProtect, &oldProtect);
				return oldMethod;
			}
			void DestroyHook() {
				DWORD oldProtect;
				VirtualProtect(m_pVMT, m_iMethodsCount * sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
				//memcpy(m_pVMT, m_pOriginalVMT, sizeof(uintptr_t) * m_iMethodsCount);			
				m_pVMT[m_iHookedMethod] = m_pOriginalVMT;
				VirtualProtect(m_pVMT, m_iMethodsCount * sizeof(uintptr_t), oldProtect, &oldProtect);
				// delete[] m_pOriginalVMT;
			}
		private:
			CVMTHook(void* pVMT, int iMethodIndex, void* fnHook) {
				m_pVMT = (void**)pVMT;
				m_iMethodsCount = GetMethodsCount();
				m_pOriginalVMT = m_pVMT[iMethodIndex];
				m_iHookedMethod = iMethodIndex;
				m_fnHookFunction = fnHook;
				//memcpy(m_pOriginalVMT, m_pVMT, sizeof(uintptr_t) * m_iMethodsCount); 

			}

			bool CanReadPointer(void* table) {

				if (!table) {
					return false;
				}
				MEMORY_BASIC_INFORMATION mbi;
				if (VirtualQuery(table, &mbi, sizeof(mbi)) && !(mbi.Protect & k_page_offlimits) && (mbi.Protect & k_page_readable)) {
					return true;
				}
				return false;
			}

			friend CVMTHook* Hook(void*, int, void*);
			friend void UnhookAll();
		};
		std::vector<CVMTHook*> CVMTHook::pVMTHooks;

		CVMTHook* Hook(void* pVMT, int iMethodIndex, void* fnHook) {
			CVMTHook* hook = new CVMTHook(pVMT, iMethodIndex, fnHook);
			CVMTHook::pVMTHooks.push_back(hook);
			return hook;
		}
		void UnhookAll() {
			for (auto& hook : CVMTHook::pVMTHooks) {
				hook->DestroyHook();
				delete hook;
			}
			CVMTHook::pVMTHooks.clear();
		}


	};


	namespace Patcher {
		class CPatch {
			BYTE* m_pOriginBytes;
			BYTE* m_pPatchBytes;
			size_t m_uPatchSize;
			LPVOID m_lpDestination;
			bool m_bIsNop;
			static std::vector<CPatch*> pPatches;
		public:
			// actually patching
			inline void ApplyPatch() {
				if (m_bIsNop) {
					Nop(m_lpDestination, m_uPatchSize); // fill with nops...
				}
				else {
					Patch(m_lpDestination, m_pPatchBytes, m_uPatchSize); // ...or with patch bytes
				}
			}
			// restore original bytes
			inline void RestorePatch() {
				Patch(m_lpDestination, m_pOriginBytes, m_uPatchSize);
			}
			// restore original bytes and delete patch
			inline void DestroyPatch() {
				RestorePatch();
				delete[] m_pOriginBytes; // seems to be no memory leak :trolling:
				delete[] m_pPatchBytes;
			}
		private:
			CPatch(void* destination, size_t patchSize, const void* patchBytes = 0) {
				m_lpDestination = (void*)destination;
				m_uPatchSize = patchSize;
				if (patchBytes) {
					m_pPatchBytes = new BYTE[m_uPatchSize];
					memcpy(m_pPatchBytes, patchBytes, m_uPatchSize);
				}
				else {
					m_bIsNop = true; // we don't need to save patch bytes because we just fill with nops
				}
				CopyOriginBytes();
			}

			static void Patch(void* destination, const void* patchBytes, size_t patchSize) { // how to "smart" encapsulate them??
				DWORD oldProtect;
				VirtualProtect(destination, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
				memcpy(destination, patchBytes, patchSize);
				VirtualProtect(destination, patchSize, oldProtect, &oldProtect);
			}
			static void Nop(void* destination, size_t patchSize) {
				DWORD oldProtect;
				VirtualProtect(destination, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
				memset(destination, 0x90, patchSize);
				VirtualProtect(destination, patchSize, oldProtect, &oldProtect);
			}
			friend CPatch* Patch(uintptr_t, const void*, size_t, bool);
			friend CPatch* Nop(uintptr_t, size_t, bool);
			friend void UnpatchAll();

			void CopyOriginBytes() {
				m_pOriginBytes = new BYTE[m_uPatchSize];
				memcpy(m_pOriginBytes, m_lpDestination, m_uPatchSize);
			}

		};
		std::vector<CPatch*> CPatch::pPatches;

		// ApplyPatch() & RestorePatch() | isSimple = true -> immediate apply/no saving bytes, no restore ( including UnpatchAll() )
		CPatch* Patch(uintptr_t destination, const void* patchBytes, size_t patchSize, bool isSimple = false) {
			if (isSimple) {
				CPatch::Patch((void*)destination, patchBytes, patchSize);
				return nullptr;
			}
			else {
				CPatch* patch = new CPatch((void*)destination, patchSize, patchBytes);
				CPatch::pPatches.push_back(patch);
				return patch;
			}
		}

		// ApplyPatch() & RestorePatch() | isSimple = true -> immediate apply/no saving bytes, no restore ( including UnpatchAll() )
		CPatch* Nop(uintptr_t destination, size_t patchSize, bool isSimple = false) {
			if (isSimple) {
				CPatch::Nop((void*)destination, patchSize);
				return nullptr;
			}
			else {
				CPatch* patch = new CPatch((void*)destination, patchSize, 0);
				CPatch::pPatches.push_back(patch);
				return patch;
			}
		}
		void UnpatchAll() {
			for (auto& patch : CPatch::pPatches) {
				patch->DestroyPatch();
				delete patch;
			}
		}
	};

	uintptr_t FindSignature(const char* moduleName, const void* signatureString, const char* mask) {

		unsigned char* signature = (unsigned char*)signatureString; // something is trolling us
		HMODULE moduleHandle = GetModuleHandle(moduleName);
		if (!moduleHandle) {
			return NULL;
		}

		uintptr_t moduleBaseAddress = (uintptr_t)moduleHandle;
		MODULEINFO moduleInfo;
		GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(MODULEINFO));
		uintptr_t moduleEndAddress = moduleBaseAddress + moduleInfo.SizeOfImage;

		size_t signatureLength = strlen(mask);

		for (uintptr_t address = moduleBaseAddress; address < moduleEndAddress - signatureLength; address++) {
			for (unsigned int signatureIterator = 0; signatureIterator < signatureLength; signatureIterator++) {
				if (mask[signatureIterator] == 'x') {
					if (*reinterpret_cast<BYTE*>(address + signatureIterator) != signature[signatureIterator]) {
						break;
					}
					else {
						if (signatureIterator == signatureLength - 1) { // parsed all signature;
							return address;
						}
					}
				}
			}

		}
		return 0;
	}


	uintptr_t FindDMAAddy(uintptr_t baseAddress, std::vector<unsigned int> offsets) {
		for (auto offset : offsets) {
			baseAddress = *reinterpret_cast<uintptr_t*>(baseAddress);
			baseAddress += offset;
		}
		return baseAddress;
	}

	/*void* GetVMTMethod(void* pObject, int iMethodIndex) {
		return (*(void***)pObject)[iMethodIndex];
	}
	*/

	// undone all hooks (VMT / JMP etc.)/patches
	void UnpatchAll() {
		Patcher::UnpatchAll();
		VMTHooker::UnhookAll();
	}

}

