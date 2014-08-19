#include "asn1/data.hh"

#include <algorithm>
#include <cctype>

namespace asn1 {

/**
 * Return whether the last day of given month in the Gregorian calender.
 */
static uint8_t last_day_of_month(uint32_t year, uint8_t month) {
    switch (month) {
        case 1:
        case 3:
        case 5:
        case 7:
        case 8:
        case 10:
        case 12:
            return 31;

        case 4:
        case 6:
        case 9:
        case 11:
            return 30;

        case 2:
            if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
                return 29;
            } else {
                return 28;
            }

        default:
            return 0;
    }
}

/**
 * Validate time.
 *
 * This function is probably not quite comprehensive, but I chose it instead of
 * linking against larger library as Boost;  ultimately, the consumer should
 * probably do extra check on it using platform date-time libraries, since that
 * is what they are likely to be using this date against anyways.
 */
static bool validate_time(const UTCTime &time) {
    if (time.month < 1 || time.month > 12) {
        return false;
    }
    if (time.day < 1 || time.day > last_day_of_month(time.year, time.month)) {
        return false;
    }

    // While things like leap seconds exist, X.680 explicitly limits ranges for
    // those values
    if (time.hour >= 24 || time.minute >= 60 || time.second >= 60) {
        return false;
    }

    return true;
}

/**
 * Parse supplied UTCTime blob and figure out whether it's valid.
 *
 * DER format:
 *   YYMMDDhhmmssZ
 * BER format:
 *   YYMMDDhhmm[ss](Z|+hhmm|-hhmm)
 */
bool UTCTimeData::do_parse() {
    std::string str = std::string(body.ccharptr(), body.size());

    // Find where the timezone marker starts; this also serves as a check that
    // string is at least as long as 10 or 12 (depending on whether it has
    // seconds)
    size_t tzpos = str.find_first_of("Z+-");
    if (tzpos != 12 && !(is_der && tzpos == 10)) {
        return false;
    }
    parsed.has_seconds = tzpos == 12;

    // Make sure all values up to timezone are digits
    if (!std::all_of(str.cbegin(), str.cbegin() + tzpos, isdigit)) {
        return false;
    }

    parsed.year = std::stoi(str.substr(0, 2));
    // ASN.1 conveniently defines years to be two lower digits of the full
    // year, but does not mention how exactly the two highest digits are meant
    // to be reconstructed.  X.509 (RFC 5280, § 4.1.2.5.1) says that "Where YY
    // is greater than or equal to 50, the year SHALL be interpreted as 19YY",
    // and we stick to that interpretation
    parsed.year += parsed.year >= 50 ? 1900 : 2000;

    parsed.month = std::stoi(str.substr(2, 2));
    parsed.day = std::stoi(str.substr(4, 2));
    parsed.hour = std::stoi(str.substr(6, 2));
    parsed.minute = std::stoi(str.substr(8, 2));
    if (parsed.has_seconds) {
        parsed.second = std::stoi(str.substr(10, 2));
    }
    if (!validate_time(parsed)) {
        return false;
    }

    if (str[tzpos] == 'Z') {
        parsed.is_nonutc = false;
        parsed.tzoffset = 0;

        // Ensure we don't have unconsumed data
        if (str.length() != tzpos + 1) {
            return false;
        }
    } else {
        if (is_der) {
            return false;
        }

        if (str.length() != tzpos + 5) {
            return false;
        }

        uint32_t tzoffset_hour = std::stoi(str.substr(tzpos + 1, 2));
        uint32_t tzoffset_minute = std::stoi(str.substr(tzpos + 3, 2));
        uint32_t tzoffset = tzoffset_hour * 60 + tzoffset_minute;
        if (tzoffset_hour >= 24 || tzoffset_minute >= 60) {
            return false;
        }

        parsed.is_nonutc = true;
        parsed.tzoffset = str[tzpos] == '-' ? -tzoffset : tzoffset;
    }

    return true;
}

#define UTCTIME_STR_MAX_LEN 64
std::string UTCTimeData::to_string() const {
    if (!valid) {
        return "[Invalid date and time]";
    }

    // First generate the timezone offset (+HHMM, -HHMM, or empty string if
    // none specified)
    char tzstr[6];
    if (parsed.is_nonutc) {
        char sign = parsed.tzoffset >= 0 ? '+' : '-';
        uint32_t tzoffset =
            (parsed.tzoffset >= 0) ? parsed.tzoffset : -parsed.tzoffset;
        snprintf(tzstr, sizeof(tzstr), "%c%2d%2d", sign, tzoffset / 60,
                 tzoffset % 60);
    } else {
        tzstr[0] = 0;
    }

    // Now format the date
    char buffer[UTCTIME_STR_MAX_LEN];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d (UTC%s)",
             parsed.year, parsed.month, parsed.day, parsed.hour, parsed.minute,
             parsed.second, tzstr);
    return std::string(buffer);
}

}
