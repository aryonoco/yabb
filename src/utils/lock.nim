# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## File locking using flock for mutual exclusion
## Ensures only one instance of YABB runs at a time

{.push raises: [].}

import std/[posix, os, times]
import ../wrappers/log
import ../types
import ../errors # lockError, lockHeldError

type
  # Immutable lock type specification
  LockType* = enum
    ltRead # F_RDLCK
    ltWrite # F_WRLCK
    ltUnlock # F_UNLCK

  FlockSpec* = object
    ## Immutable specification for a file lock
    ## Encapsulates lock parameters without mutable state
    lockType*: LockType
    whence*: int
    start*: int64
    length*: int64

  FileLock* = object
    fd: cint
    path: string
    acquired: bool

# Constructors for FlockSpec
# Note: Use proc instead of func because SEEK_SET is seen as global state by strictFuncs
proc writeLockSpec*(): FlockSpec =
  ## Create spec for exclusive write lock on entire file
  FlockSpec(lockType: ltWrite, whence: SEEK_SET, start: 0, length: 0)

proc readLockSpec*(): FlockSpec =
  ## Create spec for shared read lock on entire file
  FlockSpec(lockType: ltRead, whence: SEEK_SET, start: 0, length: 0)

proc unlockSpec*(): FlockSpec =
  ## Create spec for releasing a lock
  FlockSpec(lockType: ltUnlock, whence: SEEK_SET, start: 0, length: 0)

proc toTflock(spec: FlockSpec): Tflock =
  ## Convert immutable FlockSpec to mutable Tflock for FFI
  ## Mutation is contained within this procedure
  var fl: Tflock
  fl.l_type =
    case spec.lockType
    of ltRead:
      cshort(F_RDLCK)
    of ltWrite:
      cshort(F_WRLCK)
    of ltUnlock:
      cshort(F_UNLCK)
  fl.l_whence = cshort(spec.whence)
  fl.l_start = spec.start
  fl.l_len = spec.length
  fl

proc applyLock(fd: cint, spec: FlockSpec, blocking: bool): bool =
  ## Apply lock specification to file descriptor
  ## Returns true on success, false if lock cannot be acquired
  let fl = spec.toTflock()
  let cmd = if blocking: F_SETLKW else: F_SETLK
  fcntl(fd, cmd, unsafeAddr fl) == 0

proc checkLockStatus(fd: cint, spec: FlockSpec): bool =
  ## Check if a lock would block (F_GETLK)
  ## Returns true if the lock is held by another process
  ## Mutation of Tflock is contained within this procedure
  var fl = spec.toTflock()
  if fcntl(fd, F_GETLK, addr fl) == 0:
    return fl.l_type != cshort(F_UNLCK)
  false

proc tryAcquireLockImpl(
    fd: cint, lockSpec: FlockSpec, deadline: float, path: string, timeout: int
): YabbResult[FileLock] =
  ## Internal tail-recursive implementation for lock acquisition with timeout
  if epochTime() >= deadline:
    discard close(fd)
    return err(
      lockHeldError("Another instance is running (lock held after " & $timeout & "s)")
    )
  if applyLock(fd, lockSpec, blocking = false):
    # Write PID to lock file
    discard ftruncate(fd, 0)
    let pid = $getpid()
    discard write(fd, pid.cstring, pid.len.cint)
    debug "Lock acquired", path = path, pid = pid
    return ok(FileLock(fd: fd, path: path, acquired: true))
  sleep(100)
  tryAcquireLockImpl(fd, lockSpec, deadline, path, timeout)

proc acquireLock*(path: string, timeout: int = 300): YabbResult[FileLock] =
  ## Acquire exclusive file lock with timeout
  ## - path: Path to lock file (e.g., /var/run/yabb.lock)
  ## - timeout: Maximum seconds to wait for lock (default 5 minutes)
  ## Returns FileLock on success, ecLockHeld if another instance holds lock,
  ## or ecLockError for I/O failures
  let fd = open(path.cstring, O_RDWR or O_CREAT, 0o644)
  if fd < 0:
    return err(lockError("Failed to open lock file: " & path))

  # Use immutable FlockSpec instead of mutable Tflock
  let lockSpec = writeLockSpec()
  let deadline = epochTime() + float(timeout)
  tryAcquireLockImpl(fd, lockSpec, deadline, path, timeout)

proc release*(lock: sink FileLock) =
  ## Release the file lock using sink semantics
  ## The lock value is consumed and cannot be reused
  if lock.acquired:
    # Use immutable FlockSpec instead of mutable Tflock
    discard applyLock(lock.fd, unlockSpec(), blocking = false)
    discard close(lock.fd)
    try:
      removeFile(lock.path)
    except OSError:
      discard # Ignore removal errors
    debug "Lock released", path = lock.path
  # Lock value is consumed - no mutation needed

proc isLocked*(path: string): bool =
  ## Check if lock file exists and is held by another process
  if not fileExists(path):
    return false

  let fd = open(path.cstring, O_RDONLY, 0)
  if fd < 0:
    return false
  defer:
    discard close(fd)

  # Use immutable FlockSpec - mutation is contained in checkLockStatus
  checkLockStatus(fd, writeLockSpec())

{.pop.}
