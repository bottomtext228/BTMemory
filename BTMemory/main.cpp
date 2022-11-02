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

/*
	Other examples: 

	//////////////////////////////////////////////////////////
						Patches examples
	//////////////////////////////////////////////////////////

	BTMemory::Patcher::Nop(0x228, 3, true); // the last parameter is true -> return value is nullptr, so immediate apply and no restore possibility
	BTMemory::Patcher::Patch(0x228, "\0xE9\x13\x37"3, true);

	/////////////////////////////////////////////////////////

	settings::bNoRecoil = !settings::bNoRecoil;
	static auto* noRecoilPatch = BTMemory::PatcherNop(globals::baseAddress + 0x63786, 10);
	if (settings::bNoRecoil) {
		noRecoilPatch->ApplyPatch(); // change the bytes to ours
	}
	else {
		noRecoilPatch->RestorePatch(); // restore the original bytes
	}

	printf("No recoil: %s\n", settings::bNoRecoil ? "on" : "off");



	//////////////////////////////////////////////////////////
						VMT Hook example
	//////////////////////////////////////////////////////////


	typedef void(__thiscall* recoil_t)(DWORD*, float*, float*);
	recoil_t oRecoil;

	void __fastcall recoil(DWORD* pThis, void* edx, float* a2, float* a3) {
		printf("%0.2f | %0.2f\n", *a2, *a3);
		return oRecoil(pThis, a2, a3);
	}


	void* pVMT = *(void**)Misc->GetLocalPlayer()->GetWeaponById(Weapons::SUBGUN);

	auto* recoilHook = BTMemory::VMTHooker::Hook(pVMT, 5, &recoil);
	oRecoil = (recoil_t)recoilHook->ApplyHook();


	
	//////////////////////////////////////////////////////////
						Hooks examples
	//////////////////////////////////////////////////////////

	typedef void(__fastcall* fnCallBack)(int, int);
	fnCallBack oFunc;

	auto hook = BTMemory::Hooker::Hook((void*)(0x7FF6C5F210F0), funcCallBack, BTMemory::Hooker::HookType::TRAMPOLINE, 15);
	oFunc = (fnCallBack)hook->ApplyHook();

	
	//////////////////////////////////////////////////////////

	extern "C"
	{
		void detourHook(); // code in the .asm file
	};


	// Detour hooking in x64 with MSVC ( it does not support inline assembly for x64) can be done with .asm files
	BTMemory::Hooker::Hook((void*)0x7FF6C5F211AF, detourHook, BTMemory::Hooker::HookType::DETOUR, 15)->ApplyHook();


	//////////////////////////////////////////////////////////

	typedef void(__cdecl* fnCallBack)(int, int);
	fnCallBack oFunc;
	// there is no need to specify the size of the hook in redirect hooks
	oFunc = (fnCallBack)BTMemory::Hooker::Hook((void*)0x8B11B2, funcCallBack, BTMemory::Hooker::HookType::REDIRECT)->ApplyHook();



	//////////////////////////////////////////////////////////
						Other examples
	//////////////////////////////////////////////////////////

	uintptr_t sigResult = BTMemory::FindSignature("ac_client.exe", "\x8B\x46\x0C\x0F\xBF\x88\x00\x00\x00\x00\x8B\x56\x18\x89\x0A\x8B\x76\x14\xFF\x0E",
					"xxxxxx????xxxxxxxxxx");
	if (sigResult) {
		sigResult += 0x12;
		BTMemory::Patcher::Nop(sigResult, 2, true);
	}

	//////////////////////////////////////////////////////////

	void* localPlayer = (void*)BTMemory::FindDMAAddy(0x1337, {0x4, 0xC});

*/