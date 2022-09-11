#[allow(dead_code)]
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
use crate::dns::parser::ParseError;
use bitflags::bitflags;
use std::convert::TryFrom;
use std::fmt;

macro_rules! impl_code_conversion {
    ($type:ty, $repr:ty, $valid_matches:pat) => {
        impl From<$type> for $repr {
            fn from(ec: $type) -> Self {
                ec as $repr
            }
        }

        impl TryFrom<$repr> for $type {
            type Error = ParseError;

            fn try_from(value: $repr) -> Result<$type, Self::Error> {
                match value {
                    $valid_matches => Ok(unsafe { std::mem::transmute(value) }),
                    _ => Err(ParseError::UnsupportedValue {
                        value: value.to_string(),
                        kind: stringify!($type).to_string(),
                    }),
                }
            }
        }
    };
}

/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
#[rustfmt::skip]
pub enum OpCode {
    Query  = 0,
    Iquery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

impl_code_conversion!(OpCode, u8, 0 | 1 | 2 | 4 | 5);

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpCode::Query => write!(f, "QUERY"),
            OpCode::Iquery => write!(f, "IQUERY"),
            OpCode::Status => write!(f, "STATUS"),
            OpCode::Notify => write!(f, "NOTIFY"),
            OpCode::Update => write!(f, "UPDATE"),
        }
    }
}

/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
#[rustfmt::skip]
pub enum ErrorCode {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp   = 4,
    Refused  = 5,
    YXDomain = 6,
    YXRRSet  = 7,
    NXRRSet  = 8,
    NotAuth  = 9,
    NotZone  = 10,
}

impl_code_conversion!(ErrorCode, u8, 0..=10);

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::NoError => write!(f, "NOERROR"),
            ErrorCode::FormErr => write!(f, "FORMERR"),
            ErrorCode::ServFail => write!(f, "SERVFAIL"),
            ErrorCode::NXDomain => write!(f, "NXDOMAIN"),
            ErrorCode::NotImp => write!(f, "NOTIMP"),
            ErrorCode::Refused => write!(f, "REFUSED"),
            ErrorCode::YXDomain => write!(f, "YXDOMAIN"),
            ErrorCode::YXRRSet => write!(f, "YXRRSET"),
            ErrorCode::NXRRSet => write!(f, "NXRRSET"),
            ErrorCode::NotAuth => write!(f, "NOTAUTH"),
            ErrorCode::NotZone => write!(f, "NOTZONE"),
        }
    }
}

bitflags! {
    pub struct Flags: u8 {
        const QR = 0b0001_0000;
        const AA = 0b0000_1000;
        const TC = 0b0000_0100;
        const RD = 0b0000_0010;
        const RA = 0b0000_0001;
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(Flags::QR) {
            write!(f, " qr")?;
        }

        if self.contains(Flags::AA) {
            write!(f, " aa")?;
        }

        if self.contains(Flags::TC) {
            write!(f, " tc")?;
        }

        if self.contains(Flags::RD) {
            write!(f, " rd")?;
        }

        if self.contains(Flags::RA) {
            write!(f, " ra")?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub id: u16,
    pub op_code: OpCode,
    pub status: ErrorCode,
    pub flags: Flags,
    pub question_count: u16,
    pub answer_count: u16,
    pub auth_count: u16,
    pub additional_count: u16,
}
