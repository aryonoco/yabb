# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Retention policy period calculations
## Determines time boundaries for hourly, daily, weekly, monthly, yearly retention

# Pure module - enable maximum strict modes
{.experimental: "strictFuncs".}
{.experimental: "strictCaseObjects".}

import std/[times]

type RetentionPeriod* = enum
  rpHourly
  rpDaily
  rpWeekly
  rpMonthly
  rpYearly

{.push raises: [].}

proc getPeriodBoundaries*(
    period: RetentionPeriod, index: int, referenceTime: DateTime
): tuple[start, stop: DateTime] =
  ## Get start/end times for a retention period
  ## - period: The type of period (hourly, daily, etc.)
  ## - index: 0-indexed period offset from reference (0 = most recent complete period)
  ## - referenceTime: The reference time to calculate from
  case period
  of rpHourly:
    let hourStart = referenceTime - initDuration(hours = index + 1)
    result.start = dateTime(
      hourStart.year,
      hourStart.month,
      hourStart.monthday,
      hourStart.hour,
      0,
      0,
      zone = utc(),
    )
    result.stop = result.start + initDuration(hours = 1) - initDuration(seconds = 1)
  of rpDaily:
    let dayStart = referenceTime - initDuration(days = index + 1)
    result.start =
      dateTime(dayStart.year, dayStart.month, dayStart.monthday, 0, 0, 0, zone = utc())
    result.stop = result.start + initDuration(days = 1) - initDuration(seconds = 1)
  of rpWeekly:
    # Find Monday of target week
    let currentWeekday = referenceTime.weekday.ord
    let mondayOffset = currentWeekday
    let targetMonday = referenceTime - initDuration(days = mondayOffset + (7 * index))
    result.start = dateTime(
      targetMonday.year,
      targetMonday.month,
      targetMonday.monthday,
      0,
      0,
      0,
      zone = utc(),
    )
    result.stop = result.start + initDuration(days = 7) - initDuration(seconds = 1)
  of rpMonthly:
    # Use direct modular arithmetic instead of while loop
    # Convert to total months from epoch, subtract offset, convert back
    let totalMonths = referenceTime.year * 12 + referenceTime.month.ord - 1 - index - 1
    let year = totalMonths div 12
    let month = (totalMonths mod 12) + 1
    result.start = dateTime(year, Month(month), 1, 0, 0, 0, zone = utc())
    # Last day of month
    let nextMonth =
      if month == 12:
        dateTime(year + 1, mJan, 1, 0, 0, 0, zone = utc())
      else:
        dateTime(year, Month(month + 1), 1, 0, 0, 0, zone = utc())
    result.stop = nextMonth - initDuration(seconds = 1)
  of rpYearly:
    let targetYear = referenceTime.year - index - 1
    result.start = dateTime(targetYear, mJan, 1, 0, 0, 0, zone = utc())
    result.stop = dateTime(targetYear, mDec, 31, 23, 59, 59, zone = utc())

proc isInPeriod*(timestamp: DateTime, periodStart, periodEnd: DateTime): bool =
  ## Check if timestamp falls within the period boundaries
  timestamp >= periodStart and timestamp <= periodEnd

proc getPeriodKey*(period: RetentionPeriod, timestamp: DateTime): string =
  ## Get a unique key for a period (for deduplication)
  case period
  of rpHourly:
    timestamp.format("yyyy-MM-dd-HH")
  of rpDaily:
    timestamp.format("yyyy-MM-dd")
  of rpWeekly:
    # ISO week number
    let weekNum = (timestamp.yearday div 7) + 1
    $timestamp.year & "-W" & (if weekNum < 10: "0" else: "") & $weekNum
  of rpMonthly:
    timestamp.format("yyyy-MM")
  of rpYearly:
    $timestamp.year

{.pop.}
