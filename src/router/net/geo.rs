use libm::atan2;
use rkyv::{Archive, Deserialize, Serialize};
use std::cmp::Ordering;
use std::f64::consts::PI;
use std::fmt;
use std::ops::{Add, Mul, Sub};

pub const BIG_BLUE_SPHERE_DIAMETER: Distance = Distance {
    unit: DistanceUnit::Kilometers,
    value: 6378.137,
};

#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize, PartialEq)]
#[archive(check_bytes)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize, PartialEq, Default)]
#[archive(check_bytes)]
pub struct Location {
    pub latitude: f64,
    pub longitude: f64,
}

impl Location {
    pub fn from(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
        }
    }

    pub fn distance(&self, other: &Location) -> Distance {
        let (lat1, lng1) = (self.latitude, self.longitude);
        let (lat2, lng2) = (other.latitude, other.longitude);

        let pi_180 = |x: f64| (x * PI) / 180.;
        let d_lat = pi_180(lat2) - pi_180(lat1);
        let d_lng = pi_180(lng2) - pi_180(lng1);

        let a = (d_lat / 2.).sin().powf(2.)
            + pi_180(lat2).cos().powf(2.) * (d_lng / 2.).sin().powf(2.);

        let c = 2. * atan2(a.sqrt(), (1. - a).sqrt());

        BIG_BLUE_SPHERE_DIAMETER * c
    }

    pub fn add(&self, distance: &Distance, direction: Direction) -> Self {
        let d = distance.kilometers() / BIG_BLUE_SPHERE_DIAMETER.kilometers();
        let c = 180. / PI;

        match direction {
            Direction::East | Direction::West => {
                let offset = d * c / (self.latitude * PI / 180.).cos();
                let scalar = if direction == Direction::East {
                    1.
                } else {
                    -1.
                };

                Self {
                    latitude: self.latitude,
                    longitude: self.longitude + (offset * scalar),
                }
            }

            Direction::North | Direction::South => {
                let offset = d * c;
                let scalar = if direction == Direction::North {
                    1.
                } else {
                    -1.
                };

                Self {
                    latitude: self.latitude + (offset * scalar),
                    longitude: self.longitude,
                }
            }
        }
    }

    pub fn estimate_distance(&self, other: &Location) -> f64 {
        let lat_dif = (self.latitude - other.latitude).abs();
        let lng_dif = (self.longitude - other.longitude).abs();
        lat_dif + lng_dif
    }

    pub fn to_string(&self) -> String {
        format!("{},{}", self.latitude, self.longitude)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub fn find_center_point(locations: Vec<&Location>) -> Location {
    let (total_lat, total_lng) = locations.iter().fold(
        (0.0, 0.0),
        |(alat, alng),
         Location {
             latitude,
             longitude,
         }| { (alat + latitude, alng + longitude) },
    );

    let f_lat = total_lat / locations.len() as f64;
    let f_lng = total_lng / locations.len() as f64;

    Location::from(f_lat, f_lng)
}

#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize, PartialEq)]
#[archive(check_bytes)]
pub enum DistanceUnit {
    Centimeters,
    Meters,
    Kilometers,

    Inches,
    Feet,
    Yards,
    Miles,
}

impl DistanceUnit {
    pub fn in_meters(&self) -> f64 {
        match self {
            DistanceUnit::Centimeters => 0.01,
            DistanceUnit::Meters => 1.,
            DistanceUnit::Kilometers => 1000.,

            DistanceUnit::Inches => 0.0254,
            DistanceUnit::Feet => 0.3048,
            DistanceUnit::Yards => 0.9144,
            DistanceUnit::Miles => 1609.344,
        }
    }

    fn abbreviation(&self) -> String {
        match self {
            DistanceUnit::Centimeters => "cm",
            DistanceUnit::Meters => "m",
            DistanceUnit::Kilometers => "km",

            DistanceUnit::Inches => "in",
            DistanceUnit::Feet => "ft",
            DistanceUnit::Yards => "yd",
            DistanceUnit::Miles => "mi",
        }
        .into()
    }

    #[allow(dead_code)]
    fn name(&self) -> String {
        match self {
            DistanceUnit::Centimeters => "centimeters",
            DistanceUnit::Meters => "meters",
            DistanceUnit::Kilometers => "kilometers",

            DistanceUnit::Inches => "inches",
            DistanceUnit::Feet => "feet",
            DistanceUnit::Yards => "yards",
            DistanceUnit::Miles => "miles",
        }
        .into()
    }
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct Distance {
    unit: DistanceUnit,
    value: f64,
}

impl Distance {
    pub fn from(value: f64, unit: DistanceUnit) -> Self {
        Self { value, unit }
    }

    pub fn from_kilometers(value: f64) -> Self {
        Self::from(value, DistanceUnit::Kilometers)
    }

    pub fn from_meters(value: f64) -> Self {
        Self::from(value, DistanceUnit::Meters)
    }

    #[allow(dead_code)]
    pub fn from_miles(value: f64) -> Self {
        Self::from(value, DistanceUnit::Miles)
    }

    pub fn convert_to(&self, unit: DistanceUnit) -> Self {
        if self.unit == unit {
            self.clone()
        } else {
            let ratio = self.unit.in_meters() / unit.in_meters();
            let new_value = self.value * ratio;
            Self::from(new_value, unit)
        }
    }

    pub fn in_unit(&self, unit: DistanceUnit) -> f64 {
        self.convert_to(unit).value
    }

    pub fn meters(&self) -> f64 {
        self.in_unit(DistanceUnit::Meters)
    }

    pub fn kilometers(&self) -> f64 {
        self.in_unit(DistanceUnit::Kilometers)
    }

    #[allow(dead_code)]
    pub fn miles(&self) -> f64 {
        self.in_unit(DistanceUnit::Miles)
    }

    pub fn to_string(&self) -> String {
        format!("{:.1}{}", self.value, self.unit.abbreviation())
    }
}

const APPROX_EQUAL_PLACES: u8 = 3;
fn approx_equal(a: f64, b: f64, decimal_places: u8) -> bool {
    let factor = 10.0f64.powi(decimal_places as i32);
    let a = (a * factor).trunc();
    let b = (b * factor).trunc();
    a == b
}

impl PartialEq for Distance {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let a = self.in_unit(self.unit);
        let b = other.in_unit(self.unit);
        approx_equal(a, b, APPROX_EQUAL_PLACES)
    }
}

impl PartialOrd for Distance {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.in_unit(self.unit)
            .partial_cmp(&other.in_unit(self.unit))
    }
}

impl Add for Distance {
    type Output = Self;

    fn add(self, other: Distance) -> Self {
        Self::from(self.value + other.in_unit(self.unit), self.unit)
    }
}

impl Sub for Distance {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self::from(self.value - other.in_unit(self.unit), self.unit)
    }
}

impl Mul<f64> for Distance {
    type Output = Self;

    fn mul(self, multiplier: f64) -> Self {
        Self::from(self.value * multiplier, self.unit)
    }
}

impl Default for Distance {
    fn default() -> Self {
        Self::from_meters(0.)
    }
}

impl fmt::Display for Distance {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_equality() {
        let distance_a = Distance::from_kilometers(10.);
        let distance_b = Distance::from_miles(6.213712);
        let distance_c = Distance::from_kilometers(1.25);

        assert!(distance_a == distance_b);
        assert!(distance_a != distance_c);
    }

    #[test]
    fn unit_conversion() {
        let distance_a = Distance::from_miles(5.2);
        let distance_b = Distance::from_kilometers(8.368589);

        assert!(distance_a.convert_to(DistanceUnit::Kilometers) == distance_b);
    }

    #[test]
    fn measure_distance() {
        let location_a = Location::from(40.7885447, -111.7656248);
        let location_b = Location::from(40.7945846, -111.6950349);
        let distance_a = location_a.distance(&location_b);
        let distance_b = Distance::from_kilometers(5.9868);

        assert!(distance_a == distance_b);
    }

    #[test]
    fn add_distance_to_point() {
        let location_a = Location::from(40.7885447, -111.7656248);
        let distance_a = Distance::from_kilometers(8.2);

        let location_b = location_a.add(&distance_a, Direction::North);
        let location_result = Location::from(40.8622065532978, -111.7656248);

        assert!(location_b == location_result)
    }
}
