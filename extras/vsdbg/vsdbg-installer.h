/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2013 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
// <ORIGINAL-AUTHOR>: Michal Nir
// <COMPONENT>: vsdbg
// <FILE-TYPE>: component public header

#ifndef VSDBG_INSTALLER
#define VSDBG_INSTALLER

namespace VSDBG {

#include <string>

/*! 
* A type that tells the vsdbg connection status.
*/
enum VSDBG_STATUS {
    VSDBG_STATUS_DEBUGGER_ALREADY_ATTACHED,
    VSDBG_STATUS_ATTACH_ERROR,
    VSDBG_STATUS_ATTACH_TIMEOUT,
    VSDBG_STATUS_OK
} ;

/*!
* Signature of function "EnableDebuggerIntegration"
* Attaches VSDBG to the current process. 
* This function must be invoked from the context of a Visual Studio process (e.g. from a Visual Studio add-in)
*  @param[in]  pinInstallDir32  Pin kit 32 bit install directory path.
*  @param[in]  pinInstallDir64  Pin kit 64 bit install directory path.
*  @param[in]  vsdbgInstallDir32 Path to 32bit version of vsdbg.dll install directory.
*  @param[in]  vsdbgInstallDir64  Path to 64bit version of vsdbg.dll install directory.
*                           
*
*  @return    VSDBG_STATUS_DEBUGGER_ALREADY_ATTACHED - if a debugger is already attached to the process.
*             VSDBG_STATUS_ATTACH_TIMEOUT - if attach to vsdbg failed because of a timeout.
*             VSDBG_STATUS_OK - if attach to vsdbg succedded. 
*
*/
extern "C" VSDBG_STATUS EnableDebuggerIntegration(const wchar_t* pinInstallDir32,
    const wchar_t* pinInstallDir64,
    const wchar_t* vsdbgInstallDir32,
    const wchar_t* vsdbgInstallDir64);

} //namespace
#endif // file guard

