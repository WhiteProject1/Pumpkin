use std::str::FromStr;

pub enum MaybeRelativeCoordinate<const IS_Y: bool> {
    Absolute(f64),
    Relative(f64),
}

/// Parses a coordinate, rejecting non-finite values (`NaN`, `inf`) which `f64::from_str` accepts.
fn parse_finite(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|e| format!("{e}"))?;
    if v.is_finite() {
        Ok(v)
    } else {
        Err(format!("Coordinate must be finite: {s}"))
    }
}

impl<const IS_Y: bool> TryFrom<&str> for MaybeRelativeCoordinate<IS_Y> {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(s) = s.strip_prefix('~') {
            let offset = if s.is_empty() { 0.0 } else { parse_finite(s)? };
            Ok(Self::Relative(offset))
        } else {
            let mut v = parse_finite(s)?;

            // set position to block center if no decimal place is given
            if !IS_Y && !s.contains('.') {
                v += 0.5;
            }

            Ok(Self::Absolute(v))
        }
    }
}

impl<const IS_Y: bool> MaybeRelativeCoordinate<IS_Y> {
    pub fn into_absolute(self, origin: Option<f64>) -> Option<f64> {
        match self {
            Self::Absolute(v) => Some(v),
            Self::Relative(offset) => {
                let v = origin? + offset;
                v.is_finite().then_some(v)
            }
        }
    }
}

#[derive(Debug)]
pub enum MaybeRelativeBlockCoordinate<const IS_Y: bool> {
    Absolute(i32),
    Relative(i32),
}

impl<const IS_Y: bool> TryFrom<&str> for MaybeRelativeBlockCoordinate<IS_Y> {
    type Error = <i32 as FromStr>::Err;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Some(s) = s.strip_prefix('~') {
            let offset = if s.is_empty() { 0 } else { s.parse()? };
            Ok(Self::Relative(offset))
        } else {
            Ok(Self::Absolute(s.parse()?))
        }
    }
}

impl<const IS_Y: bool> MaybeRelativeBlockCoordinate<IS_Y> {
    pub fn into_absolute(self, origin: Option<f64>) -> Option<i32> {
        let abs = match self {
            Self::Absolute(v) => v,
            Self::Relative(offset) => (origin?.floor() as i32).checked_add(offset)?,
        };

        // TODO
        // if IS_Y && (abs < WORLD_LOWEST_Y.into() || abs >= WORLD_MAX_Y.into()) {
        //     return None;
        // }

        Some(abs)
    }
}
