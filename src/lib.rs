//! # Features
//!
//! - `serde` — Enable serializing and deserializing [`CveId`] using `serde` v1

#![deny(unsafe_code)]
#![cfg_attr(not(any(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg_hide))]
#![cfg_attr(docsrs, doc(cfg_hide(docsrs)))]

#[cfg(feature = "serde")]
extern crate alloc;

// TODO: Ord
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CveId {
    // TODO: u8 would be sufficient for e.g. 1900 + 255 = 2155
    year: CveYear,
    // TODO: the JSON schema specifies 4-19 digits, but u32 would provide 4_294_967_295 MAX which already seems plenty per year
    number: CveNumber,
}

pub type CveYear = u16;
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

    #[inline]
    pub const fn new(year: CveYear, number: CveNumber) -> Self {
        Self { year, number }
    }

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

        Ok(Self { year, number })
    }

    pub const fn year(&self) -> CveYear {
        self.year
    }

    pub const fn number(&self) -> CveNumber {
        self.number
    }

    // https://www.cve.org/ResourcesSupport/AllResources/CNARules#section_5-4_Example_or_Test_CVE_IDs
    pub const fn is_example_or_test(&self) -> bool {
        1900 == self.year
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
        write!(f, "CVE-{:04}-{:04}", self.year, self.number)
    }
}

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
    use crate::CveId;
    use ::serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use ::serde::ser::{Serialize, SerializeStruct, Serializer};
    use alloc::string::{String, ToString};

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for CveId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
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
                let s = String::deserialize(deserializer)?;
                CveId::from_str(&s).map_err(de::Error::custom)
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

    #[cfg(test)]
    mod tests {
        use crate::CveId;
        use claims::{assert_ok, assert_ok_eq};
        use serde::{Deserialize, Serialize};
        use serde_assert::{Deserializer, Serializer, Token};

        #[test]
        fn test_serialize_binary() {
            let serializer = Serializer::builder().is_human_readable(false).build();

            let cve_id = CveId::new(1999, 1);

            assert_ok_eq!(
                cve_id.serialize(&serializer),
                [
                    Token::Struct {
                        name: "CveId",
                        len: 2
                    },
                    Token::Field("year"),
                    Token::U16(1999),
                    Token::Field("number"),
                    Token::U64(1),
                    Token::StructEnd
                ]
            );
        }

        #[test]
        fn test_serialize_human() {
            let serializer = Serializer::builder().is_human_readable(true).build();

            let cve_id = CveId::new(1999, 1);

            assert_ok_eq!(
                cve_id.serialize(&serializer),
                [Token::Str("CVE-1999-0001".to_string())]
            );
        }

        #[test]
        fn test_deserialize_binary() {
            let mut deserializer = Deserializer::builder([
                Token::Struct {
                    name: "CveId",
                    len: 2,
                },
                Token::Field("year"),
                Token::U16(1999),
                Token::Field("number"),
                Token::U64(1),
                Token::StructEnd,
            ])
            .is_human_readable(false)
            .build();

            let cve_id = CveId::new(1999, 1);

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }

        #[test]
        fn test_deserialize_human() {
            let mut deserializer = Deserializer::builder([Token::Str("CVE-1999-0001".to_string())])
                .is_human_readable(true)
                .build();

            let cve_id = CveId::new(1999, 1);

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }

        #[test]
        fn test_roundtrip_binary() {
            let cve_id = CveId::new(1999, 1);

            let serializer = Serializer::builder().is_human_readable(false).build();
            let mut deserializer = Deserializer::builder(assert_ok!(cve_id.serialize(&serializer)))
                .is_human_readable(false)
                .build();

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }

        #[test]
        fn test_roundtrip_human() {
            let cve_id = CveId::new(1999, 1);

            let serializer = Serializer::builder().is_human_readable(true).build();
            let mut deserializer = Deserializer::builder(assert_ok!(cve_id.serialize(&serializer)))
                .is_human_readable(true)
                .build();

            assert_ok_eq!(CveId::deserialize(&mut deserializer), cve_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_debug() {
        assert_eq!(
            format!("{:?}", CveId::new(1999, 1)),
            "CveId { year: 1999, number: 1 }"
        );
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", CveId::new(1999, 1)), "CVE-1999-0001");
        assert_eq!(format!("{}", CveId::new(1900, 424242)), "CVE-1900-424242");
    }

    #[test]
    fn test_from_str() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(CveId::from_str("CVE-1999-0001")?, CveId::new(1999, 1));
        assert_eq!(
            CveId::from_str("CVE-1900-424242")?,
            CveId::new(1900, 424242)
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
    fn test_fromstr() {
        assert_eq!("CVE-1999-0001".parse(), Ok(CveId::new(1999, 1)));
    }

    #[test]
    fn test_isexampleortest() {
        assert!(CveId::new(1900, 666).is_example_or_test());
        assert!(!CveId::new(1999, 1).is_example_or_test());
    }
}

#[cfg(doctest)]
#[doc=include_str!("../README-crate.md")]
mod readme {}
