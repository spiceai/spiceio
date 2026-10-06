//! Preconditions evaluated while the server holds the destination's mutation lock.

use std::{fmt, io};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum WriteCondition {
    #[default]
    None,
    Absent,
    Match(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionFailure {
    PreconditionFailed,
    NoSuchKey,
    Conflict,
}

impl fmt::Display for ConditionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreconditionFailed => "the destination precondition did not hold",
            Self::NoSuchKey => "the destination does not exist",
            Self::Conflict => "the conditional write conflicted with another operation",
        })
    }
}

impl std::error::Error for ConditionFailure {}

impl From<ConditionFailure> for io::Error {
    fn from(value: ConditionFailure) -> Self {
        Self::other(value)
    }
}

impl WriteCondition {
    pub fn check(&self, etag: Option<&str>) -> io::Result<()> {
        match (self, etag) {
            (Self::None | Self::Absent, None) | (Self::None, Some(_)) => Ok(()),
            (Self::Absent, Some(_)) => Err(ConditionFailure::PreconditionFailed.into()),
            (Self::Match(_), None) => Err(ConditionFailure::NoSuchKey.into()),
            (Self::Match(expected), Some(actual)) if expected == "*" || expected == actual => {
                Ok(())
            }
            (Self::Match(_), Some(_)) => Err(ConditionFailure::PreconditionFailed.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_distinguish_absence_and_stale_versions() {
        assert!(WriteCondition::Absent.check(None).is_ok());
        assert!(WriteCondition::Absent.check(Some("v1")).is_err());
        let c = WriteCondition::Match("v1".into());
        assert!(c.check(Some("v1")).is_ok());
        assert!(c.check(Some("v2")).is_err());
        let e = c.check(None).unwrap_err();
        assert_eq!(
            e.get_ref().unwrap().downcast_ref(),
            Some(&ConditionFailure::NoSuchKey)
        );
    }
}
