#pragma once
#include <Windows.h>
#include <vector>

namespace BTMemory {
	class CPatch {
		BYTE* m_pOriginBytes;
		BYTE* m_pPatchBytes;
		size_t m_uPatchSize;
		LPVOID m_lpDestination;
		bool m_bIsNop;
	public:
		CPatch(void* destination,  size_t patchSize, const void* patchBytes = 0) {
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
	
	private:	
		void CopyOriginBytes() {
			m_pOriginBytes = new BYTE[m_uPatchSize];
			memcpy(m_pOriginBytes, m_lpDestination, m_uPatchSize);
		}
		
	};
	

	std::vector<CPatch*> pPatches;

	// ApplyPatch() & RestorePatch() | isSimple = true -> immediate apply/no saving bytes, no restore ( including UnpatchAll() )
	CPatch* Patch(uintptr_t destination, const void* patchBytes, size_t patchSize, bool isSimple = false) {
		if (isSimple) {
			CPatch::Patch((void*)destination, patchBytes, patchSize);
			return nullptr;
		}
		else {
			CPatch* patch = new CPatch((void*)destination, patchSize, patchBytes);
			pPatches.push_back(patch);
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
			pPatches.push_back(patch);
			return patch;
		}
	}

	void UnpatchAll() {
		for (auto& patch : pPatches) {
			patch->DestroyPatch();
			delete patch;
		}
		pPatches.clear();
	}
}

