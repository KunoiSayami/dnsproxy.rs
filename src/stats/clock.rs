//! Local wall-clock time for stats record timestamps and file names, which
//! `dnsstat.py` writes in local time with a UTC offset.

use std::time::{SystemTime, UNIX_EPOCH};

/// A calendar date and time in the local time zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    offset_secs: i64,
}

impl LocalTime {
    /// `time` in the local time zone (UTC where it can't be determined).
    pub fn at(time: SystemTime) -> Self {
        let epoch = match time.duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => -(e.duration().as_secs() as i64),
        };
        Self::from_epoch(epoch, utc_offset_secs(epoch))
    }

    fn from_epoch(epoch: i64, offset_secs: i64) -> Self {
        let local = epoch + offset_secs;
        let (year, month, day) = civil_from_days(local.div_euclid(86_400));
        let secs = local.rem_euclid(86_400) as u32;
        Self {
            year,
            month,
            day,
            hour: secs / 3600,
            minute: secs / 60 % 60,
            second: secs % 60,
            offset_secs,
        }
    }

    /// `YYYY-MM-DD`, the stats file name stem.
    pub fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// `YYYY-MM-DDTHH:MM:SS+HH:MM`, like Python's
    /// `datetime.astimezone().isoformat(timespec="seconds")`.
    pub fn iso8601(&self) -> String {
        let sign = if self.offset_secs < 0 { '-' } else { '+' };
        let offset = self.offset_secs.unsigned_abs();
        format!(
            "{}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
            self.date(),
            self.hour,
            self.minute,
            self.second,
            offset / 3600,
            offset / 60 % 60,
        )
    }
}

/// The local time zone's UTC offset at `epoch`, from the C library, which
/// reads `TZ` and `/etc/localtime`.
#[cfg(unix)]
fn utc_offset_secs(epoch: i64) -> i64 {
    // Converted to `time_t`, inferred from `localtime_r`'s signature: the
    // `libc` crate deprecates naming the alias on musl, where its width is
    // set to change. Infallible where it's 64-bit, but not on 32-bit
    // targets with a 32-bit `time_t` (some OpenWrt devices).
    #[allow(irrefutable_let_patterns, clippy::useless_conversion)]
    let Ok(t) = epoch.try_into() else {
        return 0;
    };
    // SAFETY: `localtime_r` is the reentrant variant: it only reads `t` and
    // writes the caller-owned `tm`, which is plain data.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::localtime_r(&t, &mut tm) };
    if result.is_null() {
        0
    } else {
        // `c_long`: i64 here, but i32 on 32-bit targets.
        #[allow(clippy::useless_conversion)]
        i64::from(tm.tm_gmtoff)
    }
}

#[cfg(not(unix))]
fn utc_offset_secs(_epoch: i64) -> i64 {
    0
}

/// Converts days since 1970-01-01 to a proleptic Gregorian `(year, month,
/// day)`, per Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_with_offset() {
        // 2026-11-09T07:40:05Z
        let epoch = 1_794_210_005;
        let shanghai = LocalTime::from_epoch(epoch, 8 * 3600);
        assert_eq!(shanghai.iso8601(), "2026-11-09T15:40:05+08:00");
        assert_eq!(shanghai.date(), "2026-11-09");
        let utc = LocalTime::from_epoch(epoch, 0);
        assert_eq!(utc.iso8601(), "2026-11-09T07:40:05+00:00");
        let newfoundland = LocalTime::from_epoch(epoch, -(3 * 3600 + 1800));
        assert_eq!(newfoundland.iso8601(), "2026-11-09T04:10:05-03:30");
    }

    #[test]
    fn civil_dates_cross_month_year_and_leap_boundaries() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }
}
