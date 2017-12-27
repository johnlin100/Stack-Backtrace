#include <Base.h>

#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/DebugLib.h>

#include <IndustryStandard/PeImage.h>

typedef struct {
  UINT32  BeginRVA;
  UINT32  EndRVA;
  UINT32  UnwindInfo;
} EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY;

//
// Defined the UNWIND OP CODE
//
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128,     /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        UINT8 CodeOffset;
        UINT8 UnwindOp : 4;            // defined in UNWIND_CODE_OPS
        UINT8 OpInfo   : 4;
    } OPCODE;
    UINT16 FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

//
// The data structure of a function's unwind information in X64
//
typedef struct _UNWIND_INFO {
    UINT8 Version       : 3;
    UINT8 Flags         : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
*   union {
*       OPTIONAL ULONG ExceptionHandler;
*       OPTIONAL ULONG FunctionEntry;
*   };
*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

/**
  If Pe32Data is NULL, then ASSERT().

  @param  Pe32Data   The pointer to the PE/COFF image that is loaded in system
                     memory.

  @return The PDB file name for the PE/COFF image specified by Pe32Data or NULL
          if it cannot be retrieved.

**/
VOID *
EFIAPI
PeCoffLoaderGetExceptionPointerAndSize (
  IN VOID  *Pe32Data,
  OUT UINT32 *Size
  )
{
  EFI_IMAGE_DOS_HEADER                  *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION   Hdr;
  EFI_IMAGE_DATA_DIRECTORY              *DirectoryEntry;
  EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY  *FunctionEntry;
  UINT32                                NumberOfRvaAndSizes;
  UINT16                                Magic;

  ASSERT (Pe32Data   != NULL);

  DirectoryEntry      = NULL;
  FunctionEntry       = NULL;
  NumberOfRvaAndSizes = 0;

  DosHdr = (EFI_IMAGE_DOS_HEADER *)Pe32Data;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    //
    // DOS image header is present, so read the PE header after the DOS image header.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINTN) Pe32Data + (UINTN) ((DosHdr->e_lfanew) & 0x0ffff));
  } else {
    //
    // DOS image header is not present, so PE header is at the image base.
    //
    Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)Pe32Data;
  }

  if (Hdr.Te->Signature == EFI_TE_IMAGE_HEADER_SIGNATURE) {
    FunctionEntry = NULL;
  } else if (Hdr.Pe32->Signature == EFI_IMAGE_NT_SIGNATURE) {
    //
    // NOTE: We use Machine field to identify PE32/PE32+, instead of Magic.
    //       It is due to backward-compatibility, for some system might
    //       generate PE32+ image with PE32 Magic.
    //
    switch (Hdr.Pe32->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
      //
      // Assume PE32 image with IA32 Machine field.
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case IMAGE_FILE_MACHINE_X64:
    case IMAGE_FILE_MACHINE_IA64:
      //
      // Assume PE32+ image with x64 or IA64 Machine field
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      //
      // For unknow Machine field, use Magic in optional Header
      //
      Magic = Hdr.Pe32->OptionalHeader.Magic;
    }

    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset get Debug Directory Entry
      //
      NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
      if (DirectoryEntry->VirtualAddress) {
        FunctionEntry  = (EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY *) ((UINTN) Pe32Data + DirectoryEntry->VirtualAddress);
      }
      *Size          = DirectoryEntry->Size;
    } else if (Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      //
      // Use PE32+ offset get Debug Directory Entry
      //
      NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
      DirectoryEntry = (EFI_IMAGE_DATA_DIRECTORY *)&(Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
      if (DirectoryEntry->VirtualAddress) {
        FunctionEntry  = (EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY *) ((UINTN) Pe32Data + DirectoryEntry->VirtualAddress);
      }
      *Size          = DirectoryEntry->Size;
    }

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
      DirectoryEntry = NULL;
      FunctionEntry = NULL;
    }
  } else {
    return NULL;
  }

  if (FunctionEntry == NULL || DirectoryEntry == NULL) {
    return NULL;
  }

  return FunctionEntry;
}


//
// Get Unwind Information Pointer of the function located by the address pass into.
//
VOID *
GetFunctionUnwindInfoPointer (
  IN  UINTN              Address,
  OUT UINTN              *Pe32Data,
  OUT UINTN              *FunctionStart,
  OUT UINTN              *FunctionEnd
  )
{
  UINT32                               Size;
  EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY *FunctionEntry;
  UINTN                                UnwindInfo;
  UINTN                                Offset;
  
  if (Pe32Data == NULL || FunctionStart == NULL || FunctionEnd == NULL) {
    return NULL;
  }
  
  Size = 0;
  UnwindInfo = 0;
  FunctionEntry = NULL;
  
  *Pe32Data = PeCoffSearchImageBase (Address);
  if (*Pe32Data == 0) {
    DEBUG ((DEBUG_ERROR, "!!!! Can't find image information. !!!!\n"));
    return NULL;
  } else {
    FunctionEntry = PeCoffLoaderGetExceptionPointerAndSize ((VOID *) *Pe32Data, &Size);
    Address -= *Pe32Data;
    
    if (FunctionEntry == NULL || Size == 0) {
      DEBUG ((DEBUG_ERROR, "!!!! Can't find Function entry\n"));
      return NULL;
    }
    
    Offset = 0;
    while (TRUE) {
      if (Offset >= Size) {
        break;
      }
      
      if (Address >= FunctionEntry->BeginRVA && Address < FunctionEntry->EndRVA) {
        UnwindInfo = (UINTN) *Pe32Data + FunctionEntry->UnwindInfo;
        *FunctionStart = (UINTN) *Pe32Data + FunctionEntry->BeginRVA;
        *FunctionEnd = (UINTN) *Pe32Data + FunctionEntry->EndRVA;
        break;
      }
      
      Offset += sizeof (EFI_IMAGE_X64_RUNTIME_FUNCTION_ENTRY);
      FunctionEntry ++;
    }
    
    return (VOID *) UnwindInfo;
  }
}

//
// Register String Array
//
CHAR8 *mRegisterInfo [] = {
  "rax",
  "rcx",
  "rdx",
  "rbx",
  "rsp",
  "rbp",
  "rsi",
  "rdi",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15"
  };

//
// Decode Dump the Unwind Code information
// 
//
UINTN
DumpUnwindCode (
  IN UINT8                             CodeOffset,
  IN UINT8                             UnwindOp,
  IN UINT8                             OpInfo,
  IN UINTN                             FrameOffset,
  IN BOOLEAN                           Verbose
  )
{
  UINTN  ShiftSize;

  ShiftSize = 0;
  
  switch (UnwindOp) {
    case UWOP_PUSH_NONVOL:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: PUSH_NONVOL, register=%a\n", CodeOffset, mRegisterInfo[OpInfo]));
      }
      ShiftSize = 8;
      break;
    case UWOP_ALLOC_LARGE:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: ALLOC_LARGE, size=0x%X\n", CodeOffset, FrameOffset * 8));
      }
      ShiftSize = FrameOffset * 8;
      break;
    case UWOP_ALLOC_SMALL:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: ALLOC_SMALL, size=0x%X\n", CodeOffset, OpInfo * 8 + 8));
      }
      ShiftSize = OpInfo * 8 + 8;
      break;
    case UWOP_SET_FPREG:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: SET_FPREG\n", CodeOffset));
      }
      break;
    case UWOP_SAVE_NONVOL:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: SAVE_NONVOL, register=%a offset=0x%X\n", CodeOffset, mRegisterInfo[OpInfo], FrameOffset * 8));
      }
      break;
    case UWOP_SAVE_NONVOL_FAR:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: SAVE_NONVOL_FAR, register=%a offset=0x%X\n", CodeOffset, mRegisterInfo[OpInfo], FrameOffset * 8));
      }
      break;
    case UWOP_SAVE_XMM128:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: SAVE_XMM128, register=XMM%d offset=0x%X\n", CodeOffset, OpInfo, FrameOffset));
      }
      break;
    case UWOP_SAVE_XMM128_FAR:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: SAVE_XMM128_FAR, register=XMM%d offset=0x%X\n", CodeOffset, OpInfo, FrameOffset));
      }
      break;
    case UWOP_PUSH_MACHFRAME:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "      %02X: PUSH_MACHFRAME, error=%d\n", CodeOffset, OpInfo));
      }
      break;
    default:
      if (Verbose) {
        DEBUG ((DEBUG_INFO, "Unknow UNWIND_OP\n"));
      }
      break;
  }
  
  return ShiftSize;
}

//
// Get the function's unwind offset illustrated how many bytes was occupied in stack by function prologue.
//
UINTN
GetFunctionUnwindInfo (
  IN  UINTN              Address,
  OUT UINTN              *Pe32Data,
  OUT UINTN              *FunctionStart,
  OUT UINTN              *FunctionEnd
  )
{
  UNWIND_INFO                          *UnwindInfo;
  UINTN                                CountOfCodes;
  UNWIND_CODE                          *UnwindCode;
  UINTN                                CodeIndex;

  UINT8                                CodeOffset;
  UINT8                                UnwindOp;
  UINT8                                OpInfo;
  UINTN                                FrameOffset;
  UINTN                                StackOffset;
  
  UnwindInfo = (UNWIND_INFO *) GetFunctionUnwindInfoPointer (Address, Pe32Data, FunctionStart, FunctionEnd);
  
  if (! UnwindInfo) {
    return 0xFFFFFFFF;
  }
  
  CountOfCodes = UnwindInfo->CountOfCodes;
  UnwindCode = UnwindInfo->UnwindCode;
  
  StackOffset = 0;
  CodeIndex = 0;
  while (TRUE) {
    if (CodeIndex >= CountOfCodes) {
      break;
    }
    
    CodeOffset = UnwindCode->OPCODE.CodeOffset;
    UnwindOp = UnwindCode->OPCODE.UnwindOp;
    OpInfo = UnwindCode->OPCODE.OpInfo;
    
    switch (UnwindOp) {
      case UWOP_SAVE_NONVOL:
      case UWOP_SAVE_XMM128:
      case UWOP_ALLOC_LARGE:
      case UWOP_SAVE_NONVOL_FAR:
      case UWOP_SAVE_XMM128_FAR:
        UnwindCode ++;
        CodeIndex ++;
        FrameOffset = UnwindCode->FrameOffset;
      default:
        break;
    }
    
    if (UnwindOp == UWOP_SAVE_NONVOL_FAR || UnwindOp == UWOP_SAVE_XMM128_FAR || (UnwindOp == UWOP_ALLOC_LARGE && OpInfo == 1)) {
      UnwindCode ++;
      CodeIndex ++;
      FrameOffset += UnwindCode->FrameOffset << (sizeof (UNWIND_CODE) * 8);
    }
    
    StackOffset += DumpUnwindCode (CodeOffset, UnwindOp, OpInfo, FrameOffset, FALSE);
    
    CodeIndex ++;
    UnwindCode ++;
    
  }
  
  return StackOffset;
}

//
// TraceBack the caller address and dump the information.
//
VOID
TraceBackCaller (
  IN UINTN      Level
)
{
  UINTN Offset;
  UINTN AddrOfRetAddr;
  UINTN RetAddr;
  UINTN Pe32Data;
  UINTN FunctionStart;
  UINTN FunctionEnd;
  UINTN Index;
  
  AddrOfRetAddr = (UINTN) _AddressOfReturnAddress();
  RetAddr = (UINTN) *((VOID **) AddrOfRetAddr);
  
  DEBUG ((DEBUG_INFO, "0. Addr of Return Addr : 0x%x\n", AddrOfRetAddr));
  DEBUG ((DEBUG_INFO, "0. Return Addr         : 0x%x\n", RetAddr));
  
  for (Index = 1; Index <= Level; Index ++) {
    //
    // Get current function unwind offset(bytes)
    //
    Offset = GetFunctionUnwindInfo (RetAddr, &Pe32Data, &FunctionStart, &FunctionEnd);
    if (Offset == 0 || Offset == 0xFFFFFFFF) {
      break;
    }
    DEBUG ((DEBUG_INFO, "===============\n"));
    DEBUG ((DEBUG_INFO, "%d. %08X  %08X  %08X\n", Index, Pe32Data, FunctionStart - Pe32Data, FunctionEnd - Pe32Data));
    DEBUG ((DEBUG_INFO, "%d. Offset    = %x\n", Index, Offset));
    //
    // Shift cuurent address of function's return address to caller's 
    // by adding function unwind offset(Offset) and the offset of return address itself(8).
    //
    AddrOfRetAddr += Offset + 8;
    RetAddr = (UINTN) *((VOID **) AddrOfRetAddr);
    DEBUG ((DEBUG_INFO, "%d. Addr of Return Addr = 0x%x\n", Index, AddrOfRetAddr));
    DEBUG ((DEBUG_INFO, "%d. Return Addr         = 0x%x\n", Index, RetAddr));
    DEBUG ((DEBUG_INFO, "===============\n"));
  }
}