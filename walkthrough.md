# Walkthrough - Discord Webhook Bot

I have implemented a Discord webhook bot that fetches transit alerts, deduplicates them, and sends notifications to a Discord channel.

## Changes

### Dependencies
Added the following to `Cargo.toml`:
- `reqwest`, `serde`, `serde_json`, `tokio`, `chrono`, `sha2`, `hex`, `dotenv`, `diesel`.

### Data Structures (`src/models.rs`)
- Implemented `AlertsResponse`, `AspenisedAlert`, `Route`, `SerializableStop` and supporting structs.
- Removed `diesel` macros from `Route` to allow standalone compilation without a database schema.

### Core Logic (`src/main.rs`)
- **Fetching**: Fetches alerts from the two configured endpoints every 60 seconds.
- **Deduplication**: Computes a SHA256 hash of the alert content. Stores the hash and `last_seen` timestamp in `alert_store.json`.
- **Persistence**: Loads state on startup and saves after every fetch cycle.
- **Cleanup**: Removes alerts not seen for 24 hours.
- **Discord Integration**: Sends a rich embed to the configured `DISCORD_WEBHOOK_URL` for rail alerts and `DISCORD_BUS_WEBHOOK_URL` for bus alerts.

## Verification Results

### compilation
The project compiles successfully with `cargo build`.

### Dry Run
Ran the bot with dummy webhook URLs:
```bash
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/rail/dummy" \
DISCORD_BUS_WEBHOOK_URL="https://discord.com/api/webhooks/bus/dummy" \
cargo run
```

**Output:**
```
Bot started. Checking for alerts every 60 seconds...
Checking for alerts...
New alert 9fd813a1... detected. Sending notification.
Sent webhook for 9fd813a1...
...
```

### Persistence
Verified that `alert_store.json` is created and populated with alert hashes.

## How to Run

1.  Set the `DISCORD_WEBHOOK_URL` and `DISCORD_BUS_WEBHOOK_URL` environment variables.
2.  Run with `cargo run`.

```bash
export DISCORD_WEBHOOK_URL="your_rail_webhook_url"
export DISCORD_BUS_WEBHOOK_URL="your_bus_webhook_url"
cargo run
```
