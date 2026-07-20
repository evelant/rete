//! Runtime-neutral monotonic time primitives.

use core::ops::{Add, Mul, Sub};

/// A process-local monotonic instant represented as microseconds.
///
/// The value has no wall-clock meaning and must only be compared with values
/// produced by the same runtime clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    /// Construct an instant from a runtime-owned monotonic microsecond count.
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Construct a coarse instant from whole seconds.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000))
    }

    /// Return the underlying monotonic microsecond count.
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Return the whole-second floor of this instant.
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Return the saturating duration elapsed since `earlier`.
    pub const fn saturating_duration_since(self, earlier: Self) -> MonotonicDuration {
        MonotonicDuration(self.0.saturating_sub(earlier.0))
    }

    /// Add a duration, saturating at the maximum representable instant.
    pub const fn saturating_add(self, duration: MonotonicDuration) -> Self {
        Self(self.0.saturating_add(duration.0))
    }

    /// Subtract a duration, saturating at the clock origin.
    pub const fn saturating_sub(self, duration: MonotonicDuration) -> Self {
        Self(self.0.saturating_sub(duration.0))
    }
}

impl Add<MonotonicDuration> for MonotonicInstant {
    type Output = Self;

    fn add(self, rhs: MonotonicDuration) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Sub<MonotonicDuration> for MonotonicInstant {
    type Output = Self;

    fn sub(self, rhs: MonotonicDuration) -> Self::Output {
        self.saturating_sub(rhs)
    }
}

/// A non-negative monotonic duration represented as microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicDuration(u64);

impl MonotonicDuration {
    /// A zero-length duration.
    pub const ZERO: Self = Self(0);

    /// Construct a duration from microseconds.
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Construct a duration from whole seconds.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000))
    }

    /// Add durations, saturating at the maximum representable value.
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Scale a duration, saturating at the maximum representable value.
    pub const fn saturating_mul(self, factor: u64) -> Self {
        Self(self.0.saturating_mul(factor))
    }

    /// Construct the nearest representable microsecond duration from seconds.
    pub fn from_seconds_f64(seconds: f64) -> Self {
        if !seconds.is_finite() {
            return if seconds.is_sign_positive() {
                Self(u64::MAX)
            } else {
                Self::ZERO
            };
        }
        if seconds <= 0.0 {
            Self::ZERO
        } else {
            // Avoid requiring a platform libm implementation on no_std targets.
            Self((seconds * 1_000_000.0 + 0.5) as u64)
        }
    }

    /// Return the underlying microsecond count.
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Return the whole-second floor.
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Return the duration in binary64 seconds.
    pub fn as_seconds_f64(self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }
}

impl Add for MonotonicDuration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.saturating_add(rhs)
    }
}

impl Mul<u64> for MonotonicDuration {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        self.saturating_mul(rhs)
    }
}
