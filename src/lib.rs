#![deny(unsafe_code)]
#![cfg_attr(not(any(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg_hide))]
#![cfg_attr(docsrs, doc(cfg_hide(docsrs)))]

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CveId {}

pub type CveYear = u16;
pub type CveNumber = u64;

impl CveId {
    #[inline]
    pub const fn new(_year: CveYear, _number: CveNumber) -> Self {
        todo!();
    }

    pub const fn from_str(_src: &str) -> Result<Self, ParseCveIdError> {
        todo!();
    }

    pub const fn year(&self) -> CveYear {
        todo!();
    }

    pub const fn number(&self) -> CveNumber {
        todo!();
    }
}

impl core::str::FromStr for CveId {
    type Err = ParseCveIdError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::from_str(src)
    }
}

impl core::fmt::Display for CveId {
    fn fmt(&self, _f: &mut core::fmt::Formatter) -> core::fmt::Result {
        todo!();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCveIdError();

impl core::fmt::Display for ParseCveIdError {
    fn fmt(&self, _f: &mut core::fmt::Formatter) -> core::fmt::Result {
        todo!();
    }
}

impl core::error::Error for ParseCveIdError {}

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
        assert_eq!(format!("{:?}", CveId::new(1999, 1)), "CveId(1999, 1)");
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
}

#[cfg(doctest)]
#[doc=include_str!("../README-crate.md")]
mod readme {}
