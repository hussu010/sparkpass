//! Time helpers. All times are unix seconds. Only main reads the system clock.

/// Unix seconds as "YYYY-MM-DD HH:MM:SS UTC". The pass text and `systemd-run --on-calendar` use this form.
pub fn format_utc(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // civil-from-days (Howard Hinnant), for days since 1970-01-01.
    let z = days + 719_468;
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// `<n><unit>` with unit s, m, h, or d and n >= 1, as seconds.
pub fn parse_ttl(text: &str) -> Result<u64, String> {
    let units = [("s", 1), ("m", 60), ("h", 3_600), ("d", 86_400)];
    units
        .iter()
        .find_map(|(unit, secs)| Some((text.strip_suffix(unit)?, *secs)))
        // parse() also accepts "+5", so check the digits first.
        .filter(|(n, _)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|(n, secs)| n.parse::<u64>().ok()?.checked_mul(secs))
        .filter(|ttl| *ttl >= 1)
        .ok_or_else(|| format!("bad TTL '{text}': use <n>s, <n>m, <n>h, or <n>d with n >= 1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_utc_matches_known_values() {
        for (secs, text) in [
            (0, "1970-01-01 00:00:00 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (1_704_067_199, "2023-12-31 23:59:59 UTC"), // year end
            (1_704_067_200, "2024-01-01 00:00:00 UTC"),
            (1_709_210_096, "2024-02-29 12:34:56 UTC"), // leap day
            (1_791_238_200, "2026-10-05 22:10:00 UTC"),
            (2_147_483_648, "2038-01-19 03:14:08 UTC"),
            (4_107_542_400, "2100-03-01 00:00:00 UTC"), // 2100 is not a leap year
        ] {
            assert_eq!(format_utc(secs), text);
        }
    }

    #[test]
    fn format_utc_does_not_panic_at_the_limit() {
        assert!(format_utc(u64::MAX).ends_with(" UTC"));
    }

    #[test]
    fn parse_ttl_accepts_each_unit() {
        for (text, secs) in [
            ("1s", 1),
            ("90s", 90),
            ("5m", 300),
            ("24h", 86_400),
            ("7d", 604_800),
            ("007m", 420),
        ] {
            assert_eq!(parse_ttl(text), Ok(secs), "{text}");
        }
    }

    #[test]
    fn parse_ttl_refuses_bad_input() {
        for text in [
            "",
            "5",
            "m",
            "0s",
            "0m",
            "-5m",
            "+5m",
            "5x",
            "5M",
            "5 m",
            " 5m",
            "1.5h",
            "5mm",
            "m5",
            "5m\n",
            "٥m",
            "99999999999999999999d",  // n does not fit
            "18446744073709551615m", // n * 60 does not fit
        ] {
            assert!(parse_ttl(text).is_err(), "{text:?}");
        }
    }
}
