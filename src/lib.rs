//! # About CVEs
//!
//! The [Common Vulnerabilities and Exposures (CVEs) program](https://www.cve.org/About/Overview) catalogs publicly disclosed information-security vulnerabilities.
//!
//! This catalog contains one so-called CVE Record for each vulnerability.
//! Each record has an identifier ([CVE ID](https://www.cve.org/ResourcesSupport/Glossary#glossaryCVEID)) in the format "CVE-YYYY-NNNN"; that is the prefix "CVE", a 4-digit year and then a 4+digit number, separated by "-" (dashes).
//!
//! # About this crate
//!
//! This crate implements a [`CveId`] type for syntactically valid CVE IDs. It does not implement other fields of a CVE Record.
//!
//! The crate does not implement other semantic rules, e.g.
//! - CVEs were first assigned with start of the program in 1999
//! - the first number each year is 1
//!
//! Syntactically "CVE-0000-0000" and "CVE-9999-9999999999999999999" are valid.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use cve_id::{CveId, CveYear};
//!
//! let cve_min = CveId::new(0.try_into()?, 0);
//! let cve_first = "CVE-1999-0001".parse::<CveId>()?;
//! let cve_max = CveId::new(CveYear::new(9999)?, 9_999_999_999_999_999_999);
//!
//! assert!(CveId::from_str("CAN-1999-0067").is_err());
//! assert!(CveId::from_str("CVE-1900-0420")?.is_example_or_test());
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `serde` — Enable serializing and deserializing [`CveId`] using `serde` v1
//! - `schemars` — Enable JSON schema for [`CveId`] using `schemars` v1
//! - `arbitrary` — Enable generating arbitrary [`CveId`] using `arbitrary` v1

// TODO: proper CveNumber newtype and then From<(CveYear, CveNumber))> for CveId
// TODO: test data from CVE-10K
// TODO: nightly core::iter::Step
// TODO: proper private error kinds
// TODO: nightly rustc_layout_scalar_valid_range_start rustc_layout_scalar_valid_range_end rustc_nonnull_optimization_guaranteed for CveNumber
// TODO: repr transparent for newtypes

#![deny(unsafe_code)]
#![cfg_attr(not(any(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg_hide))]
#![cfg_attr(docsrs, doc(cfg_hide(docsrs)))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Common Vulnerabilities and Exposures Identifier
///
/// Id of a CVE in the "CVE-YYYY-NNNN" format.
// TODO: Ord
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CveId {
    year: CveYear,
    // TODO: the JSON schema specifies 4-19 digits, but u32 would provide 4_294_967_295 MAX which already seems plenty per year
    number: CveNumber,
}

/// Sequential number NNNN part of [`CveId`]
pub type CveNumber = u64;

const fn u8_slice_eq(left: &[u8], right: &[u8]) -> bool {
    match (left, right) {
        (left, right) => {
            let mut returned = left.len() == right.len();

            if returned {
                let mut i = 0;

                while i != left.len() {
                    if !(left[i] == right[i]) {
                        returned = false;

                        break;
                    }

                    i += 1;
                }
            }

            returned
        }
    }
}

macro_rules! int_from_ascii {
    ($func_name:ident, $int_ty:ty) => {
        const fn $func_name(src: &[u8]) -> Result<$int_ty, ParseCveIdError> {
            let mut digits = src;

            let mut result = 0;

            macro_rules! unwrap_or_PCE {
                ($option:expr) => {
                    match $option {
                        Some(value) => value,
                        None => return Err(ParseCveIdError()),
                    }
                };
            }

            #[inline(always)]
            pub const fn can_not_overflow<T>(digits: &[u8]) -> bool {
                digits.len() <= core::mem::size_of::<T>() * 2
            }

            if can_not_overflow::<$int_ty>(digits) {
                // If the len of the str is short compared to the range of the type
                // we are parsing into, then we can be certain that an overflow will not occur.
                // This bound is when `radix.pow(digits.len()) - 1 <= T::MAX` but the condition
                // above is a faster (conservative) approximation of this.
                //
                // Consider radix 16 as it has the highest information density per digit and will thus overflow the earliest:
                // `u8::MAX` is `ff` - any str of len 2 is guaranteed to not overflow.
                // `i8::MAX` is `7f` - only a str of len 1 is guaranteed to not overflow.
                while let [c, rest @ ..] = digits {
                    result *= 10 as $int_ty;
                    let x = unwrap_or_PCE!((*c as char).to_digit(10));
                    result += x as $int_ty;
                    digits = rest;
                }
            } else {
                while let [c, rest @ ..] = digits {
                    // When `radix` is passed in as a literal, rather than doing a slow `imul`
                    // the compiler can use shifts if `radix` can be expressed as a
                    // sum of powers of 2 (x*10 can be written as x*8 + x*2).
                    // When the compiler can't use these optimisations,
                    // the latency of the multiplication can be hidden by issuing it
                    // before the result is needed to improve performance on
                    // modern out-of-order CPU as multiplication here is slower
                    // than the other instructions, we can get the end result faster
                    // doing multiplication first and let the CPU spends other cycles
                    // doing other computation and get multiplication result later.
                    let mul = result.checked_mul(10 as $int_ty);
                    let x = unwrap_or_PCE!((*c as char).to_digit(10)) as $int_ty;
                    result = unwrap_or_PCE!(mul);
                    result = unwrap_or_PCE!(<$int_ty>::checked_add(result, x));
                    digits = rest;
                }
            }
            Ok(result)
        }
    };
}

int_from_ascii!(u16_from_ascii, u16);
int_from_ascii!(u64_from_ascii, u64);

impl CveId {
    const CVE_PREFIX: &[u8] = b"CVE";
    const SEPARATOR: u8 = b'-';

    /// Constructs a semantically valid CVE ID
    #[inline]
    pub const fn new(year: CveYear, number: CveNumber) -> Self {
        Self { year, number }
    }

    /// Parses a CVE ID in the "CVE-YYYY-NNNN" format
    pub const fn from_str(src: &str) -> Result<Self, ParseCveIdError> {
        let src = src.as_bytes();

        // CVE-YYYY-NNNN
        if src.len() < 13 {
            return Err(ParseCveIdError());
        }

        if src[3] != Self::SEPARATOR || src[8] != Self::SEPARATOR {
            return Err(ParseCveIdError());
        }

        // CVE -YYYY-NNNN
        let (prefix, rest) = src.split_at(3);

        if !u8_slice_eq(prefix, Self::CVE_PREFIX) {
            return Err(ParseCveIdError());
        }

        // - YYYY-NNNN
        let (_sep, rest) = rest.split_at(1);
        // YYYY -NNNN
        let (year, rest) = rest.split_at(4);
        // - NNNN
        let (_sep, number) = rest.split_at(1);

        macro_rules! unwrap_or_PCE {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(_err) => return Err(ParseCveIdError()),
                }
            };
        }

        let year = unwrap_or_PCE!(u16_from_ascii(year));
        let number = unwrap_or_PCE!(u64_from_ascii(number));

        let year = unwrap_or_PCE!(CveYear::new(year));

        Ok(Self { year, number })
    }

    /// Returns the YYYY year part of the CVE ID
    pub const fn year(&self) -> CveYear {
        self.year
    }

    /// Returns the NNNN number part of the CVE ID
    pub const fn number(&self) -> CveNumber {
        self.number
    }

    /// Returns whether the CVE ID is "for example, documentation, and testing purposes"
    ///
    /// [CVE Numbering Authority (CNA) Operational Rules - 5.4 Example or Test CVE IDs](https://www.cve.org/ResourcesSupport/AllResources/CNARules#section_5-4_Example_or_Test_CVE_IDs)
    /// specifies:
    ///
    /// > *5.4.1*
    /// > For example, documentation, and testing purposes, CVE Program participants SHOULD use CVE IDs with the prefix “CVE-1900-” that otherwise conform to the current CVE ID specification.
    /// >
    /// > *5.4.2*
    /// > CVE Program participants MUST treat CVE IDs and CVE Records using the “CVE-1900-” prefix as test or example information and MUST NOT treat them as correct, live, or production information.
    /// > The CVE Services do not support CVE IDs with this prefix.
    pub const fn is_example_or_test(&self) -> bool {
        1900 == self.year.0
    }

    // TODO: validate if .year is within 1999-$currentYear and .number  >= 1 ?
    // cf. https://github.com/CVEProject/cve-core/blob/main/src/core/CveId.ts
    // but this does not appear to be specified, just part of "CVE Services" API/impl
}

impl core::str::FromStr for CveId {
    type Err = ParseCveIdError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::from_str(src)
    }
}

impl core::fmt::Display for CveId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CVE-{}-{:04}", self.year, self.number)
    }
}

#[cfg(feature = "arbitrary")]
#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
impl<'a> arbitrary::Arbitrary<'a> for CveId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let year = arbitrary::Arbitrary::arbitrary(u)?;
        let number = arbitrary::Arbitrary::arbitrary(u)?;

        Ok(Self { year, number })
    }
}

/// Year YYYY part of [`CveId`]
///
/// Syntactically valid years are 0000 through 9999.
// TODO: u8 would be sufficient for e.g. 1900 + 255 = 2155
// TODO: Ord
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CveYear(u16);

impl CveYear {
    const YEAR_MIN: u16 = 0;
    const YEAR_MAX: u16 = 9999;
    pub const MIN: Self = CveYear(Self::YEAR_MIN);
    pub const MAX: Self = CveYear(Self::YEAR_MAX);

    /// Constructs a semantically valid CVE year
    pub const fn new(year: u16) -> Result<Self, InvalidCveYearError> {
        if year > Self::YEAR_MAX {
            return Err(InvalidCveYearError());
        }

        Ok(Self(year))
    }

    // TODO: const from_str
}

impl core::convert::TryFrom<u16> for CveYear {
    type Error = InvalidCveYearError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl core::convert::From<CveYear> for u16 {
    fn from(year: CveYear) -> Self {
        year.0
    }
}

impl PartialEq<u16> for CveYear {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl core::fmt::Display for CveYear {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:04}", self.0)
    }
}

#[cfg(feature = "arbitrary")]
#[cfg_attr(docsrs, doc(cfg(feature = "arbitrary")))]
impl<'a> arbitrary::Arbitrary<'a> for CveYear {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let year = u.int_in_range(Self::YEAR_MIN..=Self::YEAR_MAX)?;
        Ok(Self(year))
    }
}

/// Invalid value error for [`CveYear`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCveYearError();

impl core::fmt::Display for InvalidCveYearError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "invalid CVE year")
    }
}

impl core::error::Error for InvalidCveYearError {}

/// Parse error for [`CveId`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCveIdError();

impl core::fmt::Display for ParseCveIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "can not parse CVE ID")
    }
}

impl core::error::Error for ParseCveIdError {}

#[cfg(feature = "serde")]
mod serde {
    use crate::{CveId, CveYear};
    use ::serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use ::serde::ser::{Serialize, SerializeStruct, Serializer};
    use core::fmt::Write;

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for CveId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                struct Wrapper<'a> {
                    buf: &'a mut [u8],
                    offset: usize,
                }

                impl<'a> Wrapper<'a> {
                    fn new(buf: &'a mut [u8]) -> Self {
                        Wrapper {
                            buf: buf,
                            offset: 0,
                        }
                    }
                }

                impl<'a> core::fmt::Write for Wrapper<'a> {
                    fn write_str(&mut self, s: &str) -> core::fmt::Result {
                        let bytes = s.as_bytes();

                        let remainder = &mut self.buf[self.offset..];
                        if remainder.len() < bytes.len() {
                            return Err(core::fmt::Error);
                        }
                        let remainder = &mut remainder[..bytes.len()];
                        remainder.copy_from_slice(bytes);

                        self.offset += bytes.len();

                        Ok(())
                    }
                }

                // "CVE" "-" CveYear::MAX "-" CveNumber::MAX
                let mut buf = [0 as u8; 3 + 1 + 5 + 1 + 20];
                let mut wrapper = Wrapper::new(&mut buf);
                write!(wrapper, "{}", self).expect("can write to fixed buffer");
                let chars = &wrapper.buf[0..wrapper.offset];
                let s = str::from_utf8(chars).expect("valid ASCII");
                serializer.serialize_str(s)
            } else {
                let mut state = serializer.serialize_struct("CveId", 2)?;
                state.serialize_field("year", &self.year)?;
                state.serialize_field("number", &self.number)?;
                state.end()
            }
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for CveId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let s = <&str>::deserialize(deserializer)?;
                CveId::from_str(s).map_err(de::Error::custom)
            } else {
                enum Field {
                    Year,
                    Number,
                }

                impl<'de> Deserialize<'de> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        struct FieldVisitor;

                        impl<'de> Visitor<'de> for FieldVisitor {
                            type Value = Field;

                            fn expecting(
                                &self,
                                formatter: &mut core::fmt::Formatter,
                            ) -> core::fmt::Result {
                                formatter.write_str("`year` or `number`")
                            }

                            fn visit_str<E>(self, value: &str) -> Result<Field, E>
                            where
                                E: de::Error,
                            {
                                match value {
                                    "year" => Ok(Field::Year),
                                    "number" => Ok(Field::Number),
                                    _ => Err(de::Error::unknown_field(value, FIELDS)),
                                }
                            }
                        }

                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }

                struct CveIdVisitor;

                impl<'de> Visitor<'de> for CveIdVisitor {
                    type Value = CveId;

                    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                        formatter.write_str("struct CveId")
                    }

                    fn visit_seq<V>(self, mut seq: V) -> Result<CveId, V::Error>
                    where
                        V: SeqAccess<'de>,
                    {
                        let year = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                        let number = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        Ok(CveId::new(year, number))
                    }

                    fn visit_map<V>(self, mut map: V) -> Result<CveId, V::Error>
                    where
                        V: MapAccess<'de>,
                    {
                        let mut year = None;
                        let mut number = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Year => {
                                    if year.is_some() {
                                        return Err(de::Error::duplicate_field("year"));
                                    }
                                    year = Some(map.next_value()?);
                                }
                                Field::Number => {
                                    if number.is_some() {
                                        return Err(de::Error::duplicate_field("number"));
                                    }
                                    number = Some(map.next_value()?);
                                }
                            }
                        }
                        let year = year.ok_or_else(|| de::Error::missing_field("year"))?;
                        let number = number.ok_or_else(|| de::Error::missing_field("number"))?;
                        Ok(CveId::new(year, number))
                    }
                }

                const FIELDS: &[&str] = &["year", "number"];
                deserializer.deserialize_struct("CveId", FIELDS, CveIdVisitor)
            }
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for CveYear {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_newtype_struct("CveYear", &self.0)
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for CveYear {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct CveYearVisitor;

            impl<'de> Visitor<'de> for CveYearVisitor {
                type Value = CveYear;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("struct CveYear")
                }

                fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    let year = deserializer.deserialize_u16(self)?;
                    Ok(year)
                }

                fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    CveYear::new(v).map_err(E::custom)
                }
            }

            deserializer.deserialize_newtype_struct("CveYear", CveYearVisitor)
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::{CveId, CveNumber, CveYear};
        use claims::{assert_ok, assert_ok_eq};
        use serde::{Deserialize, Serialize};
        use serde_assert::{Deserializer, Serializer, Token};

        // TODO: proptest any valid CveId should roundtrip binary
        // TODO: proptest any valid CveId should roundtrip human-readable

        #[test]
        fn test_serialize_binary() -> Result<(), Box<dyn std::error::Error>> {
            let serializer = Serializer::builder().is_human_readable(false).build();

            let cve_id = CveId::new(1999.try_into()?, 1);

            assert_ok_eq!(
                cve_id.serialize(&serializer),
                [
                    Token::Struct {
                        name: "CveId",
                        len: 2
                    },
                    Token::Field("year"),
                    Token::NewtypeStruct { name: "CveYear" },
                    Token::U16(1999),
                    Token::Field("number"),
                    Token::U64(1),
                    Token::StructEnd
                ]
            );

            Ok(())
        }

        #[test]
        fn test_serialize_human() -> Result<(), Box<dyn std::error::Error>> {
            let serializer = Serializer::builder().is_human_readable(true).build();

            let cve_id = CveId::new(1999.try_into()?, 1);

            assert_ok_eq!(
                cve_id.serialize(&serializer),
                [Token::Str("CVE-1999-0001".to_string())]
            );

            Ok(())
        }

        #[test]
        fn test_deserialize_binary() -> Result<(), Box<dyn std::error::Error>> {
            let mut deserializer = Deserializer::builder([
                Token::Struct {
                    name: "CveId",
                    len: 2,
                },
                Token::Field("year"),
                Token::NewtypeStruct { name: "CveYear" },
                Token::U16(1999),
                Token::Field("number"),
                Token::U64(1),
                Token::StructEnd,
            ])
            .is_human_readable(false)
            .build();

            let cve_id = CveId::new(1999.try_into()?, 1);

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);

            Ok(())
        }

        #[test]
        fn test_deserialize_human() -> Result<(), Box<dyn std::error::Error>> {
            let mut deserializer = Deserializer::builder([Token::Str("CVE-1999-0001".to_string())])
                .is_human_readable(true)
                .build();

            let cve_id = CveId::new(1999.try_into()?, 1);

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);

            Ok(())
        }

        #[test]
        fn test_roundtrip_binary() {
            let cve_id = CveId::new(CveYear::MIN, CveNumber::MIN);

            let serializer = Serializer::builder().is_human_readable(false).build();
            let mut deserializer = Deserializer::builder(assert_ok!(cve_id.serialize(&serializer)))
                .is_human_readable(false)
                .build();

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }

        #[test]
        fn test_roundtrip_human() {
            let cve_id = CveId::new(CveYear::MAX, CveNumber::MAX);

            let serializer = Serializer::builder().is_human_readable(true).build();
            let mut deserializer = Deserializer::builder(assert_ok!(cve_id.serialize(&serializer)))
                .is_human_readable(true)
                .build();

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }
    }
}

#[cfg(feature = "schemars")]
mod schemars {
    use crate::CveId;
    use alloc::borrow::Cow;
    use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

    /// JSON schema matching `cveId` from [CVE JSON record format](https://cveproject.github.io/cve-schema/schema/docs/)
    #[cfg_attr(docsrs, doc(cfg(feature = "schemars")))]
    impl JsonSchema for CveId {
        fn schema_name() -> Cow<'static, str> {
            "CveId".into()
        }

        fn schema_id() -> Cow<'static, str> {
            "cve_id::CveId".into()
        }

        fn json_schema(_: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "pattern": r"^CVE-[0-9]{4}-[0-9]{4,19}$"
            })
        }

        fn inline_schema() -> bool {
            true
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::CveId;
        use schemars::JsonSchema;

        #[test]
        fn test_jsonschema() {
            fn assert_jsonschema<T: JsonSchema>() {}
            assert_jsonschema::<CveId>();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: proptest any str should not panic when parsing CveId
    // TODO: proptest any valid year & number should parse back equal

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CveId>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<CveId>();
    }

    #[test]
    fn test_debug() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            format!("{:?}", CveId::new(1999.try_into()?, 1)),
            "CveId { year: CveYear(1999), number: 1 }"
        );

        Ok(())
    }

    #[test]
    fn test_display() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            format!("{}", CveId::new(1999.try_into()?, 1)),
            "CVE-1999-0001"
        );
        assert_eq!(
            format!("{}", CveId::new(1900.try_into()?, 424242)),
            "CVE-1900-424242"
        );

        Ok(())
    }

    #[test]
    fn test_from_str() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            CveId::from_str("CVE-1999-0001")?,
            CveId::new(1999.try_into()?, 1)
        );
        assert_eq!(
            CveId::from_str("CVE-1900-424242")?,
            CveId::new(1900.try_into()?, 424242)
        );

        assert_eq!(CveId::from_str("hurz").unwrap_err(), ParseCveIdError());
        assert_eq!(
            CveId::from_str("cve-1999-0001").unwrap_err(),
            ParseCveIdError()
        );

        Ok(())
    }

    #[test]
    fn test_parsecveiderror_display() {
        assert_eq!(
            format!("{}", CveId::from_str("hurz").unwrap_err()),
            "can not parse CVE ID"
        );
    }

    #[test]
    fn test_fromstr() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!("CVE-1999-0001".parse(), Ok(CveId::new(1999.try_into()?, 1)));

        Ok(())
    }

    #[test]
    fn test_isexampleortest() -> Result<(), Box<dyn std::error::Error>> {
        assert!(CveId::new(1900.try_into()?, 666).is_example_or_test());
        assert!(!CveId::new(1999.try_into()?, 1).is_example_or_test());

        Ok(())
    }

    #[test]
    fn test_min() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            CveId::new(CveYear::MIN, CveNumber::MIN),
            "CVE-0000-0000".parse()?
        );

        Ok(())
    }

    #[test]
    fn test_max() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            CveId::new(CveYear::MAX, CveNumber::MAX),
            "CVE-9999-18446744073709551615".parse()?
        );

        Ok(())
    }
}

#[cfg(doctest)]
#[doc=include_str!("../README-crate.md")]
mod readme {}
