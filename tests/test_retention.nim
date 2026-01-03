# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Tests for retention policy
## Tests period boundaries and snapshot selection

import unittest
import std/[times, sets]

import ../src/types
import ../src/retention/policy
import ../src/retention/manager

suite "Retention periods":
  test "RetentionPeriod enum values":
    check rpHourly.ord == 0
    check rpDaily.ord == 1
    check rpWeekly.ord == 2
    check rpMonthly.ord == 3
    check rpYearly.ord == 4

suite "Period boundaries - Hourly":
  test "hourly period boundaries for index 0":
    let refTime = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpHourly, 0, refTime)

    # Index 0 = previous complete hour (13:00-13:59)
    check start.hour == 13
    check start.minute == 0
    check start.second == 0
    check stop.hour == 13
    check stop.minute == 59
    check stop.second == 59

  test "hourly period boundaries for index 1":
    let refTime = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpHourly, 1, refTime)

    # Index 1 = two hours ago (12:00-12:59)
    check start.hour == 12
    check stop.hour == 12

suite "Period boundaries - Daily":
  test "daily period boundaries for index 0":
    let refTime = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpDaily, 0, refTime)

    # Index 0 = yesterday
    check start.monthday == 14
    check start.hour == 0
    check start.minute == 0
    check stop.monthday == 14
    check stop.hour == 23
    check stop.minute == 59

  test "daily period crosses month boundary":
    let refTime = dateTime(2024, mFeb, 1, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpDaily, 0, refTime)

    # Should be January 31
    check start.month == mJan
    check start.monthday == 31

suite "Period boundaries - Weekly":
  test "weekly period starts on Monday":
    # January 15, 2024 is a Monday
    let refTime = dateTime(2024, mJan, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpWeekly, 0, refTime)

    # Previous complete week should start on Monday Jan 8
    check start.weekday == dMon

  test "weekly period spans 7 days":
    let refTime = dateTime(2024, mJan, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpWeekly, 0, refTime)

    let duration = stop.toTime - start.toTime
    # Should be 6 days, 23 hours, 59 minutes, 59 seconds
    check duration.inDays == 6

suite "Period boundaries - Monthly":
  test "monthly period for January reference":
    let refTime = dateTime(2024, mFeb, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpMonthly, 0, refTime)

    # Index 0 = previous month (January)
    check start.month == mJan
    check start.monthday == 1
    check stop.month == mJan
    check stop.monthday == 31

  test "monthly period handles February correctly":
    let refTime = dateTime(2024, mMar, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpMonthly, 0, refTime)

    # 2024 is a leap year, so February has 29 days
    check start.month == mFeb
    check start.monthday == 1
    check stop.month == mFeb
    check stop.monthday == 29

  test "monthly period crosses year boundary":
    let refTime = dateTime(2024, mJan, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpMonthly, 0, refTime)

    # Previous month = December 2023
    check start.month == mDec
    check start.year == 2023

suite "Period boundaries - Yearly":
  test "yearly period for index 0":
    let refTime = dateTime(2024, mJun, 15, 12, 0, 0, zone = utc())
    let (start, stop) = getPeriodBoundaries(rpYearly, 0, refTime)

    # Index 0 = previous complete year (2023)
    check start.year == 2023
    check start.month == mJan
    check start.monthday == 1
    check stop.year == 2023
    check stop.month == mDec
    check stop.monthday == 31

suite "isInPeriod":
  test "timestamp within period returns true":
    let periodStart = dateTime(2024, mJan, 1, 0, 0, 0, zone = utc())
    let periodEnd = dateTime(2024, mJan, 31, 23, 59, 59, zone = utc())
    let timestamp = dateTime(2024, mJan, 15, 12, 0, 0, zone = utc())

    check isInPeriod(timestamp, periodStart, periodEnd)

  test "timestamp before period returns false":
    let periodStart = dateTime(2024, mJan, 1, 0, 0, 0, zone = utc())
    let periodEnd = dateTime(2024, mJan, 31, 23, 59, 59, zone = utc())
    let timestamp = dateTime(2023, mDec, 31, 23, 59, 59, zone = utc())

    check not isInPeriod(timestamp, periodStart, periodEnd)

  test "timestamp after period returns false":
    let periodStart = dateTime(2024, mJan, 1, 0, 0, 0, zone = utc())
    let periodEnd = dateTime(2024, mJan, 31, 23, 59, 59, zone = utc())
    let timestamp = dateTime(2024, mFeb, 1, 0, 0, 0, zone = utc())

    check not isInPeriod(timestamp, periodStart, periodEnd)

  test "timestamp at period boundary is included":
    let periodStart = dateTime(2024, mJan, 1, 0, 0, 0, zone = utc())
    let periodEnd = dateTime(2024, mJan, 31, 23, 59, 59, zone = utc())

    check isInPeriod(periodStart, periodStart, periodEnd)
    check isInPeriod(periodEnd, periodStart, periodEnd)

suite "getPeriodKey":
  test "hourly key format":
    let ts = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let key = getPeriodKey(rpHourly, ts)
    check key == "2024-01-15-14"

  test "daily key format":
    let ts = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let key = getPeriodKey(rpDaily, ts)
    check key == "2024-01-15"

  test "monthly key format":
    let ts = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let key = getPeriodKey(rpMonthly, ts)
    check key == "2024-01"

  test "yearly key format":
    let ts = dateTime(2024, mJan, 15, 14, 30, 0, zone = utc())
    let key = getPeriodKey(rpYearly, ts)
    check key == "2024"

suite "Snapshot selection":
  test "empty list returns empty set":
    let snapshots: seq[Snapshot] = @[]
    let policy = RetentionPolicy(hourly: 24, daily: 7, weekly: 4, monthly: 6, yearly: 2)
    let result = selectSnapshotsToKeep(snapshots, policy)
    check result.len == 0

  test "single snapshot is always kept":
    let snapshots = @[
      Snapshot(
        path: "/snapshots/backup.2024-01-15T120000Z",
        name: "backup.2024-01-15T120000Z",
        timestamp: dateTime(2024, mJan, 15, 12, 0, 0, zone = utc()),
        snapshotType: stFull,
        parent: Opt.none(string),
        uuid: "uuid-1",
        verified: true
      )
    ]
    let policy = RetentionPolicy(hourly: 1, daily: 1, weekly: 1, monthly: 1, yearly: 1)
    let result = selectSnapshotsToKeep(snapshots, policy)
    check result.len == 1
    check "/snapshots/backup.2024-01-15T120000Z" in result

  test "most recent snapshot is always kept":
    let refTime = dateTime(2024, mJan, 15, 14, 0, 0, zone = utc())
    let snapshots = @[
      Snapshot(
        path: "/snapshots/old",
        name: "old",
        timestamp: dateTime(2024, mJan, 1, 12, 0, 0, zone = utc()),
        snapshotType: stFull,
        parent: Opt.none(string),
        uuid: "uuid-old",
        verified: true
      ),
      Snapshot(
        path: "/snapshots/new",
        name: "new",
        timestamp: dateTime(2024, mJan, 15, 13, 0, 0, zone = utc()),
        snapshotType: stIncremental,
        parent: Opt.some("/snapshots/old"),
        uuid: "uuid-new",
        verified: true
      )
    ]
    let policy = RetentionPolicy(hourly: 0, daily: 0, weekly: 0, monthly: 0, yearly: 0)
    let result = selectSnapshotsToKeep(snapshots, policy, refTime)

    # Even with all retention set to 0, most recent should be kept
    check "/snapshots/new" in result
