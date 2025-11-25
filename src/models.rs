use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertsResponse {
    pub alerts: HashMap<String, AspenisedAlert>,
    pub routes: HashMap<String, Route>,
    pub stops: HashMap<String, SerializableStop>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AspenisedAlert {
    pub active_period: Vec<AspenTimeRange>,
    pub informed_entity: Vec<AspenEntitySelector>,
    pub cause: Option<i32>,
    pub effect: Option<i32>,
    pub url: Option<AspenTranslatedString>,
    pub header_text: Option<AspenTranslatedString>,
    pub description_text: Option<AspenTranslatedString>,
    pub tts_header_text: Option<AspenTranslatedString>,
    pub tts_description_text: Option<AspenTranslatedString>,
    pub severity_level: Option<i32>,
    pub image: Option<AspenTranslatedImage>,
    pub image_alternative_text: Option<AspenTranslatedString>,
    pub cause_detail: Option<AspenTranslatedString>,
    pub effect_detail: Option<AspenTranslatedString>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenTimeRange {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenEntitySelector {
    pub agency_id: Option<String>,
    pub route_id: Option<String>,
    pub route_type: Option<i32>,
    pub trip: Option<AspenRawTripInfo>,
    pub stop_id: Option<String>,
    pub direction_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenRawTripInfo {
    pub trip_id: Option<String>,
    pub route_id: Option<String>,
    pub direction_id: Option<u32>,
    pub start_time: Option<String>,
    pub start_date: Option<String>,
    pub schedule_relationship: Option<String>,
    pub modified_trip: Option<Box<AspenRawTripInfo>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenTranslatedString {
    pub translation: Vec<AspenTranslation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenTranslation {
    pub text: String,
    pub language: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenTranslatedImage {
    pub localised_image: Vec<AspenLocalisedImage>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct AspenLocalisedImage {
    pub url: String,
    pub media_type: String,
    pub language: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SerializableStop {
    pub id: String,
    pub code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub location_type: i16,
    pub parent_station: Option<String>,
    pub zone_id: Option<String>,
    pub longitude: Option<f64>,
    pub latitude: Option<f64>,
    pub timezone: Option<String>,
    pub platform_code: Option<String>,
    pub level_id: Option<String>,
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub onestop_feed_id: String,
    pub attempt_id: String,
    pub route_id: String,
    pub short_name: Option<String>,
    pub short_name_translations: Option<serde_json::Value>,
    pub long_name: Option<String>,
    pub long_name_translations: Option<serde_json::Value>,
    pub gtfs_desc: Option<String>,
    pub gtfs_desc_translations: Option<serde_json::Value>,
    pub route_type: i16,
    pub url: Option<String>,
    pub url_translations: Option<serde_json::Value>,
    pub agency_id: Option<String>,
    pub gtfs_order: Option<u32>,
    pub color: Option<String>,
    pub text_color: Option<String>,
    pub continuous_pickup: i16,
    pub continuous_drop_off: i16,
    pub shapes_list: Option<Vec<Option<String>>>,
    pub chateau: String,
}
