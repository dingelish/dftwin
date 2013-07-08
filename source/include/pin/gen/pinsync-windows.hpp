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
// <ORIGINAL-AUTHOR>: Greg Lueck
// <COMPONENT>: pinvm
// <FILE-TYPE>: public header

#ifndef PINSYNC_WINDOWS_HPP
#define PINSYNC_WINDOWS_HPP

#include "sync.hpp"

namespace LEVEL_BASE {
    extern void Yield();
    extern void *EventCreate(LEVEL_BASE::BOOL, LEVEL_BASE::BOOL);
    extern VOID CloseHandle(void *);
    extern VOID EventSet(void *);
    extern VOID EventReset(void *);
    extern VOID WaitForEvent(void *);
    extern LEVEL_BASE::BOOL TimedWaitForEvent(void *, LEVEL_BASE::UINT32);
} 


namespace PINVM {


/*!
 * We use spin locks on Windows for now mostly because the implementation
 * is easy.  It would be worth investigating other options in the future.
 * This struct provides the O/S primitive that the locks need in order to
 * implement a spin-loop.
 */
struct /*<UTILITY>*/ SYNC_WINDOWS
{
    /*!
     * This is a Windows "HANDLE", but we cast to "void *".  We do this because
     * this header is included by Pin tools and we don't want to require Pin
     * tools to include <windows.h>.
     */
    typedef void *EVENT_T;

    /*!
     * Yield the processor.
     */
    static void Yield()
    {
        LEVEL_BASE::Yield();
    }

    /*!
     * Create a Windows event.
     *
     *  @param[out] event   Receives the event handle on success.
     *
     * @return  TRUE on success.
     */
    static bool EventCreate(EVENT_T *event)
    {
        EVENT_T handle = LEVEL_BASE::EventCreate(TRUE, FALSE);
        if (!handle)
            return false;
        *event = handle;
        return true;
    }

    /*!
     * Delete a Windows event.
     *
     *  @param[in] event    Handle to the event.
     */
    static void EventDelete(EVENT_T event)
    {
        LEVEL_BASE::CloseHandle(event);
    }

    /*!
     * Change an event to "signaled" state.
     *
     *  @param[in] event    Handle to the event.
     */
    static void EventSet(EVENT_T event)
    {
        LEVEL_BASE::EventSet(event);
    }

    /*!
     * Change an event to "non-signaled" state.
     *
     *  @param[in] event    Handle to the event.
     */
    static void EventClear(EVENT_T event)
    {
        LEVEL_BASE::EventReset(event);
    }

    /*!
     * Block the calling thread until an event has the "signaled" state.
     *
     *  @param[in] event    Handle to the event.
     */
    static void EventWait(EVENT_T event)
    {
        LEVEL_BASE::WaitForEvent(event);
    }

    /*!
     * Block the calling thread until an event has the "signaled" state or
     * until a timeout expires.
     *
     *  @param[in] event    Handle to the event.
     *  @param[in] timeout  The timeout value in milliseconds.
     *
     * @return  TRUE if the event has "signaled" state.
     */
    static bool EventTimedWait(EVENT_T event, unsigned timeout)
    {
        return LEVEL_BASE::TimedWaitForEvent(event, timeout);
    }
};


/*!
 * Basic non-recursive lock.
 */
typedef SYNC::SIMPLE_LOCK_SPIN<SYNC_WINDOWS> PINSYNC_LOCK;

/*!
 * Basic non-recursive lock with POD semantics.
 */
typedef SYNC::SIMPLE_LOCK_SAFEPOD_SPIN<SYNC_WINDOWS> PINSYNC_POD_LOCK;

/*!
 * Basic non-recursive lock with SAFEPOD semantics.
 */
typedef SYNC::SIMPLE_LOCK_SAFEPOD_SPIN<SYNC_WINDOWS> PINSYNC_SAFEPOD_LOCK;

/*!
 * Read-writer lock.
 */
typedef SYNC::READER_WRITER_LOCK_SPIN<SYNC_WINDOWS> PINSYNC_RWLOCK;

/*!
 * Read-writer lock with POD semantics.
 */
typedef SYNC::READER_WRITER_LOCK_SAFEPOD_SPIN<SYNC_WINDOWS> PINSYNC_POD_RWLOCK;

/*!
 * Binary semaphore.
 */
typedef SYNC::SEMAPHORE_EVENT<SYNC_WINDOWS> PINSYNC_SEMAPHORE;

/*!
 * Binary semaphore with POD semantics.
 */
typedef SYNC::SEMAPHORE_POD_EVENT<SYNC_WINDOWS> PINSYNC_POD_SEMAPHORE;

} // namespace
#endif // file guard
