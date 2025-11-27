mod models;

use chrono::{DateTime, TimeZone, Utc};
use dotenv::dotenv;
use models::{AlertsResponse, AspenisedAlert};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration as StdDuration;
use tokio::time;

const STATE_FILE: &str = "alert_store.json";
const CHECK_INTERVAL_SECONDS: u64 = 10;
const CLEANUP_AGE_HOURS: i64 = 24;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AlertState {
    hash: String,
    last_seen: DateTime<Utc>,
}

type StateStore = HashMap<String, AlertState>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let webhook_url = env::var("DISCORD_WEBHOOK_URL").expect("DISCORD_WEBHOOK_URL must be set");
    let bus_webhook_url =
        env::var("DISCORD_BUS_WEBHOOK_URL").expect("DISCORD_BUS_WEBHOOK_URL must be set");
    let accessibility_webhook_url = env::var("DISCORD_ACCESSIBILITY_WEBHOOK_URL")
        .expect("DISCORD_ACCESSIBILITY_WEBHOOK_URL must be set");

    let urls = vec![
        "https://birch.catenarymaps.org/fetchalertsofchateau/?chateau=metrolinktrains",
        "https://birch.catenarymaps.org/fetchalertsofchateau/?chateau=metro~losangeles",
    ];

    let client = Client::new();
    let mut state = load_state().unwrap_or_default();

    println!(
        "Bot started. Checking for alerts every {} seconds...",
        CHECK_INTERVAL_SECONDS
    );

    loop {
        println!("Checking for alerts...");
        for url in &urls {
            match fetch_alerts(&client, url).await {
                Ok(response) => {
                    process_alerts(
                        &client,
                        &webhook_url,
                        &bus_webhook_url,
                        &accessibility_webhook_url,
                        &mut state,
                        response,
                    )
                    .await;
                }
                Err(e) => eprintln!("Error fetching from {}: {}", url, e),
            }
        }

        cleanup_state(&mut state);
        if let Err(e) = save_state(&state) {
            eprintln!("Failed to save state: {}", e);
        }

        time::sleep(StdDuration::from_secs(CHECK_INTERVAL_SECONDS)).await;
    }
}

async fn fetch_alerts(client: &Client, url: &str) -> Result<AlertsResponse, reqwest::Error> {
    let resp = client.get(url).send().await?;
    resp.json::<AlertsResponse>().await
}

async fn process_alerts(
    client: &Client,
    webhook_url: &str,
    bus_webhook_url: &str,
    accessibility_webhook_url: &str,
    state: &mut StateStore,
    data: AlertsResponse,
) {
    for (alert_id, alert) in &data.alerts {
        // Create a canonical representation for hashing
        // We use serde_json::to_string to get a consistent string representation of the alert content
        let content_string = serde_json::to_string(&alert).unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(content_string.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let now = Utc::now();

        // Determine if it's a bus alert
        let mut is_bus = false;
        let mut is_rail = false;

        for entity in &alert.informed_entity {
            if let Some(route_type) = entity.route_type {
                if route_type == 3 {
                    is_bus = true;
                } else {
                    is_rail = true;
                }
            } else if let Some(route_id) = &entity.route_id {
                if let Some(route) = data.routes.get(route_id) {
                    if route.route_type == 3 {
                        is_bus = true;
                    } else {
                        is_rail = true;
                    }
                }
            }
        }

        // Default to rail if unknown, or if it affects both (send to both? User said separate, usually implies exclusive or both if mixed. Let's send to relevant hooks.)
        // If no specific type found, default to rail (main webhook).
        if !is_bus && !is_rail {
            is_rail = true;
        }

        // Check for accessibility keywords
        let header_text = alert
            .header_text
            .as_ref()
            .and_then(|t| t.translation.first())
            .map(|t| t.text.to_lowercase())
            .unwrap_or_default();

        let description_text = alert
            .description_text
            .as_ref()
            .and_then(|t| t.translation.first())
            .map(|t| t.text.to_lowercase())
            .unwrap_or_default();

        let is_accessibility = header_text.contains("elevator")
            || header_text.contains("escalator")
            || description_text.contains("elevator")
            || description_text.contains("escalator");

        let target_webhooks = if is_accessibility {
            vec![accessibility_webhook_url]
        } else if is_bus && is_rail {
            vec![webhook_url, bus_webhook_url]
        } else if is_bus {
            vec![bus_webhook_url]
        } else {
            vec![webhook_url]
        };

        // Check if we've seen this alert ID before
        if let Some(existing_state) = state.get_mut(alert_id) {
            if existing_state.hash == hash {
                // Same content, just update last_seen
                existing_state.last_seen = now;
                continue;
            }
            // Content changed, update hash and last_seen, and send notification
            println!("Alert {} changed. Sending notification.", alert_id);
            existing_state.hash = hash;
            existing_state.last_seen = now;
            for hook in &target_webhooks {
                send_discord_webhook(
                    client,
                    hook,
                    alert_id,
                    alert,
                    &data.routes,
                    &data.stops,
                    true,
                )
                .await;
            }
        } else {
            // New alert
            println!("New alert {} detected. Sending notification.", alert_id);
            state.insert(
                alert_id.clone(),
                AlertState {
                    hash,
                    last_seen: now,
                },
            );
            for hook in &target_webhooks {
                send_discord_webhook(
                    client,
                    hook,
                    alert_id,
                    alert,
                    &data.routes,
                    &data.stops,
                    false,
                )
                .await;
            }
        }
    }
}

fn cleanup_state(state: &mut StateStore) {
    let now = Utc::now();
    let before_count = state.len();
    state.retain(|_, s| {
        let age = now.signed_duration_since(s.last_seen);
        age.num_hours() < CLEANUP_AGE_HOURS
    });
    let removed = before_count - state.len();
    if removed > 0 {
        println!("Cleaned up {} old alerts.", removed);
    }
}

fn load_state() -> std::io::Result<StateStore> {
    if !Path::new(STATE_FILE).exists() {
        return Ok(HashMap::new());
    }
    let mut file = File::open(STATE_FILE)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let state: StateStore = serde_json::from_str(&contents)?;
    Ok(state)
}

fn save_state(state: &StateStore) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    let mut file = File::create(STATE_FILE)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

async fn send_discord_webhook(
    client: &Client,
    webhook_url: &str,
    alert_id: &str,
    alert: &AspenisedAlert,
    routes: &HashMap<String, models::Route>,
    stops: &HashMap<String, models::SerializableStop>,
    is_update: bool,
) {
    let mut agency_name = None;
    let mut route_short_name = None;
    let mut stop_name = None;
    let mut route_color = None;

    for entity in &alert.informed_entity {
        if let Some(rid) = &entity.route_id {
            if let Some(route) = routes.get(rid) {
                if agency_name.is_none() {
                    agency_name = route.agency_id.clone();
                }
                if route_short_name.is_none() {
                    route_short_name = route.short_name.clone();
                }
                if route_color.is_none() {
                    route_color = route.color.clone();
                }
            }
        }
        if let Some(sid) = &entity.stop_id {
            if let Some(stop) = stops.get(sid) {
                if stop_name.is_none() {
                    stop_name = stop.name.clone();
                }
            }
        }
        if let Some(aid) = &entity.agency_id {
            if agency_name.is_none() {
                agency_name = Some(aid.clone());
            }
        }
    }

    let mut info_parts = Vec::new();
    if let Some(agency) = agency_name {
        info_parts.push(agency);
    }
    if let Some(route) = route_short_name {
        info_parts.push(route);
    }
    if let Some(stop) = stop_name {
        info_parts.push(stop);
    }

    let info_text = info_parts.join(" / ");

    let title_text = if info_text.is_empty() {
        "Alert".to_string()
    } else {
        format!("Alert {}", info_text)
    };

    let title = if is_update {
        format!("🔄 Updated: {}", title_text)
    } else {
        title_text
    };

    let header = alert
        .header_text
        .as_ref()
        .and_then(|t| t.translation.first())
        .map(|t| t.text.clone())
        .unwrap_or_else(|| "No Header".to_string());

    let mut description = alert
        .description_text
        .as_ref()
        .and_then(|t| t.translation.first())
        .map(|t| t.text.clone())
        .unwrap_or_else(|| "No Description".to_string());

    if !alert.active_period.is_empty() {
        description.push_str("\n\n**Active Periods:**");
        for period in &alert.active_period {
            let start_str = period
                .start
                .and_then(|s| Utc.timestamp_opt(s as i64, 0).single())
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Start".to_string());

            let end_str = period
                .end
                .and_then(|s| Utc.timestamp_opt(s as i64, 0).single())
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Indefinitely".to_string());

            description.push_str(&format!("\n• {} - {}", start_str, end_str));
        }
    }

    let url = alert
        .url
        .as_ref()
        .and_then(|t| t.translation.first())
        .map(|t| t.text.clone());

    let color_int = if let Some(hex_color) = route_color {
        let clean_hex = hex_color.trim_start_matches('#');
        u32::from_str_radix(clean_hex, 16).unwrap_or(if is_update { 0xFFA500 } else { 0xFF0000 })
    } else {
        if is_update { 0xFFA500 } else { 0xFF0000 }
    };

    let mut embed = json!({
        "title": title,
        "description": header, // Using header as main description for visibility
        "fields": [
            {
                "name": "Details",
                "value": description,
                "inline": false
            }
        ],
        "color": color_int,
        "footer": {
            "text": format!("Catenary Maps • Alert ID: {}", alert_id)
        },
        "timestamp": Utc::now().to_rfc3339()
    });

    if let Some(u) = url {
        embed["url"] = json!(u);
    }

    let payload = json!({
        "embeds": [embed]
    });

    if let Err(e) = client.post(webhook_url).json(&payload).send().await {
        eprintln!("Failed to send webhook for {}: {}", alert_id, e);
    } else {
        println!("Sent webhook for {}", alert_id);
    }
}
