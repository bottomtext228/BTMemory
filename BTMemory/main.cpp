#include "BTMemory.h"


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

/*
	Other examples: 


	BTMemory::Nop(0x228, 3, true); // the last parameter is true -> return value is nullptr, so immediate apply and no restore possibility
	BTMemory::Patch(0x228, "\0xE9\x13\x37"3, true);

	/////////////////////////////////////////////////////////

	settings::bNoRecoil = !settings::bNoRecoil;
	static BTMemory::CPatch* noRecoilPatch = BTMemory::Nop(globals::baseAddress + 0x63786, 10);
	if (settings::bNoRecoil) {
		noRecoilPatch->ApplyPatch(); // change the bytes to ours
	}
	else {
		noRecoilPatch->RestorePatch(); // restore the original bytes
	}

	printf("No recoil: %s\n", settings::bNoRecoil ? "on" : "off");

*/