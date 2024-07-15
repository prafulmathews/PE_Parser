#include<Windows.h>
#include<stdio.h>
#include<string.h>


int main(int argc,char* argv[])
{
	if (argc < 2) {
		printf("Enter the name of the PE file you want to parse.\n");
		return -1;
	}
	
	char filename[MAX_PATH] = { 0 };
	strcpy_s(filename,MAX_PATH, argv[1]);
	printf("%s",filename);
	
	HANDLE hfile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("Failed to open file: %d\n",GetLastError());
		return -1;
	}

	DWORD filesize = GetFileSize(hfile, NULL);
	LPVOID filedata = HeapAlloc(GetProcessHeap(), 0, filesize);
	DWORD dwsizeread = NULL;
	if (!ReadFile(hfile, filedata, filesize, &dwsizeread, NULL)) {
		printf("Failed to read file properly\n");
		return -1;
	}
	printf("\tFile Size: %d\tFile Present At: 0x%p\n\n", filesize, filedata);

	PIMAGE_DOS_HEADER dosheader = {0};
	dosheader = (PIMAGE_DOS_HEADER)filedata;
	printf("####### DOS HEADER #######\n");
	printf("Magic Number: 0x%X\n", dosheader->e_magic);
	printf("Relative File Address of EXE Header: 0x%0.8X\n\n", dosheader->e_lfanew);

	PIMAGE_NT_HEADERS imageheader = {0};
	imageheader = (PIMAGE_NT_HEADERS)((PBYTE)dosheader+dosheader->e_lfanew);
	printf("####### NT_SIGNATURE #######\n");
	//printf("Signature: 0x%x", ntheader.Signature);
	printf("Signature: 0x%X\n\n", imageheader->Signature);
	
	printf("####### FILE_HEADER #######\n");
	
	printf("Architectue: ");
	if (imageheader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		printf("x86\n");
	}
	else if (imageheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("x64\n");
	}
	else printf("0x%X\n", imageheader->FileHeader.Machine);

	printf("FileType: ");
	if (imageheader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) {
		printf("System File\n");
	}
	else if (imageheader->FileHeader.Characteristics & IMAGE_FILE_DLL) {
		printf("DLL\n");
	}
	else if (imageheader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("EXE\n");
	}
	else printf("0x%X\n", imageheader->FileHeader.Characteristics);

	printf("Number of Sections: %d\n", imageheader->FileHeader.NumberOfSections);

	printf("Size of Optional Header: %d\n\n", imageheader->FileHeader.SizeOfOptionalHeader);

	printf("####### OPTIONAL HEADER #######\n");
	
	printf("Magic (Architecture): ");
	if (imageheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("x86 (0x10B)\n");
	}
	else if (imageheader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("x64 (0x20B)\n");
	}
	else printf("0x%X\n", imageheader->OptionalHeader.Magic);

	printf("\nRVA of Entry Point: 0x%0.8X\n", imageheader->OptionalHeader.AddressOfEntryPoint);
	printf("Actual Address of Entry Point : 0x%p\n", ((PBYTE)dosheader) + imageheader->OptionalHeader.AddressOfEntryPoint);

	printf("\nSize of code section: %d\n", imageheader->OptionalHeader.SizeOfCode);
	printf("RVA of code section: 0x%0.8X\n", imageheader->OptionalHeader.BaseOfCode);
	printf("Actual Address of Code Section: %p\n", ((PBYTE)dosheader) + imageheader->OptionalHeader.BaseOfCode);
	
	printf("\nSize of Initialized Data: %d\n", imageheader->OptionalHeader.SizeOfInitializedData);
	printf("Size of Uninitialized Data: %d\n", imageheader->OptionalHeader.SizeOfUninitializedData);
	printf("Size Of Image: %d\n", imageheader->OptionalHeader.SizeOfImage);

	printf("\nRequired Version: %d:%d\n", imageheader->OptionalHeader.MajorOperatingSystemVersion, imageheader->OptionalHeader.MinorOperatingSystemVersion);
	
	printf("File Checksum: 0x%0.8X\n", imageheader->OptionalHeader.CheckSum);

	printf("Preferred Mapping Address: 0x%p\n", imageheader->OptionalHeader.ImageBase);

	printf("Number of Enteries in the DataDirectory: %d\n\n", imageheader->OptionalHeader.NumberOfRvaAndSizes);

	printf("####### DATA DIRECTORIES #######\n");

	printf("Export Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("Import Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("Resource Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("Exception Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("Security Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);

	printf("Base Relocation Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("Debug Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

	printf("TLS Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("IAT Directory: 0x%p\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + (PBYTE)dosheader);
	printf("\t\tSize: %d", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	printf("\t\tRVA: 0x%0.8X\n\n", imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

	
	PIMAGE_SECTION_HEADER sectionheader = (PIMAGE_SECTION_HEADER)((PBYTE)imageheader + sizeof(IMAGE_NT_HEADERS));
	printf("####### SECTION HEADERS #######\n");

	for (int i = 0; i < imageheader->FileHeader.NumberOfSections; i++) {
		printf("Name: %s\n", sectionheader->Name);
		printf("\tSize: %d\n", sectionheader->SizeOfRawData);
		printf("\tRVA: 0x%0.8X\n", sectionheader->VirtualAddress);
		printf("\tAddress: 0x%p\n", sectionheader->VirtualAddress + (PBYTE)dosheader);
		printf("\tNumber of Relocations: %d", sectionheader->NumberOfRelocations);
		printf("\tPermissions: ");
		if (sectionheader->Characteristics & IMAGE_SCN_MEM_EXECUTE && sectionheader->Characteristics & IMAGE_SCN_MEM_READ) {
			printf("PAGE_EXECUTE_READWRITE");
			printf("\n");
			sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
			continue;
		}
		if (sectionheader->Characteristics & IMAGE_SCN_MEM_WRITE && sectionheader->Characteristics & IMAGE_SCN_MEM_READ) {
			printf("PAGE_READWRITE");
			printf("\n");
			sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
			continue;
		}
		if (sectionheader->Characteristics & IMAGE_SCN_MEM_READ) {
			printf("PAGE_READ");
			printf("\n");
			sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
			continue;
		}
		printf(" 0x%X", sectionheader->Characteristics);
		printf("\n");
		sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);

	}

	DWORD importtable_rva = (imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	sectionheader = (PIMAGE_SECTION_HEADER)((PBYTE)imageheader + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER importsection = NULL;
	for (int i = 0; i < imageheader->FileHeader.NumberOfSections; i++) {
		if (importtable_rva >= sectionheader->VirtualAddress && importtable_rva < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
			importsection = sectionheader;
			break;
		}
		sectionheader = (PBYTE)sectionheader + sizeof(IMAGE_SECTION_HEADER);
	}

	//DWORD importoffset = (DWORD)dosheader + importsection->PointerToRawData;
	//PIMAGE_IMPORT_DESCRIPTOR importable = (PIMAGE_IMPORT_DESCRIPTOR)(importoffset + (imageheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importsection->VirtualAddress));
	
	DWORD importoffset = importtable_rva - importsection->VirtualAddress + importsection->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR importtable = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)dosheader + importoffset);
	printf("\n\n####### IMPORT ADDRESS TABLE #######\n");

	while (importtable->Name != 0) {
		char* name = (char*)(importtable->Name - importsection->VirtualAddress+importsection->PointerToRawData + (PBYTE)dosheader);
		printf("Imported DLL: %s\n", name);
		DWORD thunkoffset = importtable->FirstThunk - importsection->VirtualAddress + importsection->PointerToRawData;
		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(thunkoffset + (PBYTE)dosheader);
		while (thunk->u1.AddressOfData != 0) {
			DWORD funcoffset = thunk->u1.AddressOfData - importsection->VirtualAddress + importsection->PointerToRawData;
			PIMAGE_IMPORT_BY_NAME funcname = (PIMAGE_IMPORT_BY_NAME)((PBYTE)dosheader + funcoffset);
			printf("\t%s\n", funcname->Name);
			thunk++;
			//thunk = thunk + sizeof(IMAGE_THUNK_DATA);
		}
		importtable++;
		printf("\n");
		//importtable = importtable + sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	return 0;
}