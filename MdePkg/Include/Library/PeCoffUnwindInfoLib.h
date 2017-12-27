/** @file
  Provides services to load and relocate a PE/COFF image.

  The PE/COFF Loader Library abstracts the implementation of a PE/COFF loader for
  IA-32, x86, IPF, and EBC processor types. The library functions are memory-based 
  and can be ported easily to any environment.
  
Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under 
the terms and conditions of the BSD License that accompanies this distribution.  
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.                                            

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,                     
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.             

**/

#ifndef __BASE_PE_COFF_UNWIND_INFO_H__
#define __BASE_PE_COFF_UNWIND_INFO_H__

#include <IndustryStandard/PeImage.h>

VOID *
EFIAPI
PeCoffLoaderGetExceptionPointerAndSize (
  IN VOID  *Pe32Data,
  OUT UINT32 *Size
  );


UINTN
GetFunctionUnwindInfo (
  IN  UINTN              Address
  );

VOID
TraceBackCaller (
  IN UINTN               Level
  );

#endif
