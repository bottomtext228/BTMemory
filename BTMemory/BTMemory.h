#pragma once
#include <Windows.h>
#include <vector>
#include <psapi.h>

#define k_page_writeable (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
#define k_page_readable (k_page_writeable|PAGE_READONLY|PAGE_WRITECOPY|PAGE_EXECUTE_READ|PAGE_EXECUTE_WRITECOPY)
#define k_page_offlimits (PAGE_GUARD|PAGE_NOACCESS)


/* TODO:
  ADD x64 support :irony:
*/
namespace BTMemory {

	namespace Hooker {
		enum class HookType {
			DETOUR, // jmp
			TRAMPOLINE, // jmp with trampoline
			REDIRECT // call
		};
		class CHook {
			const uint32_t m_fnHookCallback;
			const uint32_t m_pToHook;
			uint32_t m_fnOriginal = 0;
			BYTE* m_pOriginalBytes = 0;
			const size_t m_uHookSize;
			const HookType m_hookType;
			static std::vector<CHook*> pHooks;
		public:
			CHook(void* fnToHook, void* fnHookCallback, HookType hookType, size_t hookSize) :
				m_pToHook((uint32_t)fnToHook), m_fnHookCallback((uint32_t)fnHookCallback), m_hookType(hookType), m_uHookSize(hookSize) {
			}

			void* ApplyHook() {
				switch (m_hookType) {
				case HookType::REDIRECT:
					return InstallRedirectHook();
					break;
				case HookType::TRAMPOLINE:
					return InstallTrampolineHook();
					break;
				case HookType::DETOUR:
					InstallDetourHook();
					break;
				
				}
				return nullptr;

			}
			void DestroyHook() {
				if (m_hookType == HookType::REDIRECT) {
					DWORD oldProtect;
					VirtualProtect((void*)m_pToHook, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
					*reinterpret_cast<uint32_t*>(m_pToHook + 1) = m_fnOriginal; // restore the original relative address 
					VirtualProtect((void*)m_pToHook, 5, oldProtect, &oldProtect);
				}
				if (m_hookType == HookType::TRAMPOLINE || m_hookType == HookType::DETOUR) { // both have similar working method
					DWORD oldProtect;
					VirtualProtect((void*)m_pToHook, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
					memcpy((void*)m_pToHook, m_pOriginalBytes, m_uHookSize); // restore the original code of the function
					VirtualProtect((void*)m_pToHook, 5, oldProtect, &oldProtect);
					VirtualFree(m_pOriginalBytes, NULL, MEM_RELEASE);  // delete allocated memory for original code/trampoline

				}			
				auto index = std::find(pHooks.begin(), pHooks.end(), this); // if we are destroying the hook we should erase him from the hooks array 
				if (index != pHooks.end()) {
					pHooks.erase(index);
					delete this;
				}
				
			
			}
		private:
			void* InstallTrampolineHook() {
				
				InstallDetourHook();

				*reinterpret_cast<BYTE*>(m_pOriginalBytes + m_uHookSize) = 0xE9;
				*reinterpret_cast<uint32_t*>(m_pOriginalBytes + m_uHookSize + 1) = m_pToHook - (uint32_t)m_pOriginalBytes - m_uHookSize; // jmp to original function 
				return m_pOriginalBytes; // return trampoline 				
			}
			void* InstallRedirectHook() {
				m_fnOriginal = *reinterpret_cast<uint32_t*>(m_pToHook + 1); // get original relative address 
				DWORD oldProtect;
				VirtualProtect((void*)m_pToHook, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
				uint32_t relativeAddress = m_fnHookCallback - m_pToHook - 5;
				*reinterpret_cast<uint32_t*>(m_pToHook + 1) = relativeAddress;
				VirtualProtect((void*)m_pToHook, 5, oldProtect, &oldProtect);
				return (void*)(m_pToHook + m_fnOriginal + 5); // calculate normal address of the original function  

			}
			void InstallDetourHook() {
				size_t memoryToAllocate = m_uHookSize;
				if (m_hookType == HookType::TRAMPOLINE) {
					memoryToAllocate += 5; // for jmp + relative address 
				}
				DWORD oldProtect;

				m_pOriginalBytes = (BYTE*)VirtualAlloc(0, memoryToAllocate, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // FIXED bug with non executable(access error) trampoline

				if (!m_pOriginalBytes) {
					return; // sad
				}
				VirtualProtect((void*)m_pToHook, m_uHookSize, PAGE_EXECUTE_READWRITE, &oldProtect);
				memcpy(m_pOriginalBytes, (void*)m_pToHook, m_uHookSize); // copy original bytes
			
				memset((void*)(m_pToHook), 0x90, m_uHookSize); // fill with nops in case if we replace some bytes
				
				*reinterpret_cast<BYTE*>(m_pToHook) = 0xE9;
				uint32_t callbackRelativeAddress = m_fnHookCallback - m_pToHook - 5;
				*reinterpret_cast<uint32_t*>(m_pToHook + 1) = callbackRelativeAddress; // jmp to our hook function


				VirtualProtect((void*)m_pToHook, m_uHookSize, oldProtect, &oldProtect);
			}
			friend CHook* Hook(void*, void*, HookType, size_t);
			friend void UnhookAll();
		};
		std::vector<CHook*> CHook::pHooks;
		// ApplyHook() & DestroyHook() 
		CHook* Hook(void* fnToHook, void* fnHookCallback, HookType hookType, size_t hookSize = 5) {
			CHook* hook = new CHook(fnToHook, fnHookCallback, hookType, hookSize);
			CHook::pHooks.push_back(hook);
			return hook;
		}
		void UnhookAll() {
			for (auto& hook : CHook::pHooks) {
				hook->DestroyHook();
			}
		}
	};
	namespace VMTHooker {
		class CVMTHook {
			void* m_pOriginalVMT;
			void** m_pVMT;
			const int m_iHookedMethod; 
			void* m_fnHookFunction;
			static std::vector<CVMTHook*> pVMTHooks;

		public:
			void* ApplyHook() {				
				void* oldMethod = m_pVMT[m_iHookedMethod];
				DWORD oldProtect;
				VirtualProtect(m_pVMT + m_iHookedMethod, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
				m_pVMT[m_iHookedMethod] = m_fnHookFunction; // changing the pointer to the method
				VirtualProtect(m_pVMT + m_iHookedMethod, sizeof(uintptr_t), oldProtect, &oldProtect);
				return oldMethod;
			}
			void DestroyHook() {
				DWORD oldProtect;
				VirtualProtect(m_pVMT + m_iHookedMethod, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
				//memcpy(m_pVMT, m_pOriginalVMT, sizeof(uintptr_t) * m_iMethodsCount);			
				m_pVMT[m_iHookedMethod] = m_pOriginalVMT; // restoring the pointer
				VirtualProtect(m_pVMT + m_iHookedMethod, sizeof(uintptr_t), oldProtect, &oldProtect);
				// delete[] m_pOriginalVMT;
				auto index = std::find(pVMTHooks.begin(), pVMTHooks.end(), this); // if we are destroying the hook we should erase him from the hooks array 
				if (index != pVMTHooks.end()) {
					pVMTHooks.erase(index);
					delete this;
				}		
			}
		private:
			CVMTHook(void* pVMT, int iMethodIndex, void* fnHook) :
				m_pVMT((void**)pVMT), m_pOriginalVMT(((void**)pVMT)[iMethodIndex]), m_iHookedMethod(iMethodIndex), m_fnHookFunction(fnHook) {
				// fixed bug (access violation) with m_pVMT[iMethodIndex]
			}
		
			friend CVMTHook* Hook(void*, int, void*);
			friend void UnhookAll();
		};
		std::vector<CVMTHook*> CVMTHook::pVMTHooks;
		// ApplyHook() & DestroyHook() | 
		CVMTHook* Hook(void* pVMT, int iMethodIndex, void* fnHook) {
			CVMTHook* hook = new CVMTHook(pVMT, iMethodIndex, fnHook);
			CVMTHook::pVMTHooks.push_back(hook);
			return hook;
		}
		void UnhookAll() {
			for (auto& hook : CVMTHook::pVMTHooks) {
				hook->DestroyHook();
			}
		}


	};


	namespace Patcher {
		class CPatch {
			BYTE* m_pOriginalBytes = 0;
			BYTE* m_pPatchBytes;
			const size_t m_uPatchSize;
			const LPVOID m_lpDestination;
			bool m_bIsNop = false;
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
				Patch(m_lpDestination, m_pOriginalBytes, m_uPatchSize);
			}
			// restore original bytes and delete patch
			inline void DestroyPatch() {
				RestorePatch();
				VirtualFree(m_pOriginalBytes, NULL, MEM_RELEASE); // seems to be no memory leak :trolling:
				VirtualFree(m_pPatchBytes, NULL, MEM_RELEASE);
				//delete[] m_pOriginalBytes; 
				//delete[] m_pPatchBytes;
				auto index = std::find(pPatches.begin(), pPatches.end(), this); // if we are destroying the patch we should erase him from the patch array 
				if (index != pPatches.end()) {
					pPatches.erase(index);
					delete this;
				}
			}
		private:
			CPatch(void* destination, size_t patchSize, const void* patchBytes = 0) 
			: m_lpDestination((void*)destination), m_uPatchSize(patchSize) {
				if (patchBytes) {
					m_pPatchBytes = (BYTE*)VirtualAlloc(0, m_uPatchSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					if (!m_pPatchBytes) {
						return; // sad
					}
					memcpy(m_pPatchBytes, patchBytes, m_uPatchSize);
				}
				else {
					m_bIsNop = true; // we don't need to save patch bytes because we just fill with nops
				}
				CopyOriginBytes();
			}

			static void Patch(void* destination, const void* patchBytes, size_t patchSize) { 
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
				m_pOriginalBytes = (BYTE*)VirtualAlloc(0, m_uPatchSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (!m_pOriginalBytes) {
					return; // sad
				}
				memcpy(m_pOriginalBytes, m_lpDestination, m_uPatchSize);
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

		
		uintptr_t moduleEndAddress = moduleBaseAddress + reinterpret_cast<IMAGE_NT_HEADERS*>
			(moduleBaseAddress + reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBaseAddress)->e_lfanew)->OptionalHeader.SizeOfImage;

		for (uintptr_t address = moduleBaseAddress; address < moduleEndAddress; address++) {
			unsigned int signatureIterator = 0;	
			while (mask[signatureIterator] != '\0') {
				if (mask[signatureIterator] != '?' && *reinterpret_cast<BYTE*>(address + signatureIterator) != signature[signatureIterator]) {				
					break;				
				}
				signatureIterator++;
			}
			if (!mask[signatureIterator]) {
				return address;
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

	// undone all hooks (VMT / JMP etc.)/patches
	void UnpatchAll() {
		Patcher::UnpatchAll();
		VMTHooker::UnhookAll();
		Hooker::UnhookAll();
	}

}

