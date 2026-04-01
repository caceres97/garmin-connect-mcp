# garmin-connect-mcp

MCP server for Garmin Connect. Access your fitness, health, and training data from Claude Code, Claude Desktop, Cursor, Windsurf, ChatGPT Developer Mode, or any MCP client.

**61 tools** across 7 categories: activities, daily health, trends, sleep, body composition, performance/training, and profile/devices.

API endpoints and authentication flow based on [`python-garminconnect`](https://github.com/cyberjunky/python-garminconnect) by [cyberjunky](https://github.com/cyberjunky).

## Requirements

- Node.js 20+
- A Garmin Connect account (email and password)

## Installation

### Claude Code

```bash
claude mcp add garmin -e GARMIN_EMAIL=you@email.com -e GARMIN_PASSWORD=yourpass -- npx -y @nicolasvegam/garmin-connect-mcp
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "garmin": {
      "command": "npx",
      "args": ["-y", "@nicolasvegam/garmin-connect-mcp"],
      "env": {
        "GARMIN_EMAIL": "you@email.com",
        "GARMIN_PASSWORD": "yourpass"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "garmin": {
      "command": "npx",
      "args": ["-y", "@nicolasvegam/garmin-connect-mcp"],
      "env": {
        "GARMIN_EMAIL": "you@email.com",
        "GARMIN_PASSWORD": "yourpass"
      }
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "garmin": {
      "command": "npx",
      "args": ["-y", "@nicolasvegam/garmin-connect-mcp"],
      "env": {
        "GARMIN_EMAIL": "you@email.com",
        "GARMIN_PASSWORD": "yourpass"
      }
    }
  }
}
```

### Any MCP Client

Run the server with environment variables:

```bash
GARMIN_EMAIL=you@email.com GARMIN_PASSWORD=yourpass npx -y @nicolasvegam/garmin-connect-mcp
```

By default the server runs on stdio for local clients. If `MCP_TRANSPORT=http` is set, or if `PORT`/`MCP_PORT` is present, it runs as a remote Streamable HTTP MCP server.

## Remote MCP for ChatGPT

ChatGPT Developer Mode supports remote MCP servers over Streamable HTTP and SSE. This server now supports remote Streamable HTTP deployments, which makes it usable from ChatGPT when hosted on your own server.

Recommended environment variables for remote deployment without OAuth:

```bash
GARMIN_EMAIL=you@email.com
GARMIN_PASSWORD=yourpass
MCP_TRANSPORT=http
PORT=3000
MCP_HOST=0.0.0.0
MCP_PATH=/mcp-your-secret-path
```

Use a long random `MCP_PATH` when deploying without OAuth. Example:

```bash
MCP_PATH=/mcp-4e7dd0d4b6b54f6db9d5f4d1a1fa9f8b
```

Available HTTP routes:

- `GET /` returns server info
- `GET /health` returns health status
- `POST/GET/DELETE {MCP_PATH}` serves the MCP endpoint

The ChatGPT app URL is:

```text
https://your-domain.com/mcp-your-secret-path
```

## OAuth for ChatGPT Developer Mode

This server can now expose an OAuth 2.1 authorization server that is compatible with ChatGPT Developer Mode MCP apps.

Enable it with:

```bash
GARMIN_EMAIL=you@email.com
GARMIN_PASSWORD=yourpass
MCP_TRANSPORT=http
PORT=3000
MCP_HOST=0.0.0.0
MCP_PATH=/mcp-your-secret-path
MCP_PUBLIC_BASE_URL=https://your-domain.com
MCP_OAUTH_ENABLED=true
MCP_OAUTH_USERNAME=admin
MCP_OAUTH_PASSWORD=change-this
```

When OAuth is enabled, the server exposes:

- `GET/POST /authorize`
- `POST /token`
- `POST /register`
- `POST /revoke`
- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource{MCP_PATH}`

The server advertises support for:

- `mcp:tools`
- `offline_access`

`offline_access` is important for ChatGPT because it allows refresh tokens to be issued and lets ChatGPT keep the connector working after the original access token expires.

## Deploy on Coolify

This repo now includes a production `Dockerfile`, so Coolify can deploy it directly from Git.

1. Create a new service in Coolify from this repository.
2. Use the included `Dockerfile`.
3. Set these environment variables in Coolify:
   - `GARMIN_EMAIL`
   - `GARMIN_PASSWORD`
   - `MCP_TRANSPORT=http`
   - `PORT=3000`
   - `MCP_HOST=0.0.0.0`
   - `MCP_PATH=/mcp-your-secret-path`
   - `MCP_PUBLIC_BASE_URL=https://your-domain.com`
4. If you want OAuth in ChatGPT, also set:
   - `MCP_OAUTH_ENABLED=true`
   - `MCP_OAUTH_USERNAME`
   - `MCP_OAUTH_PASSWORD`
   - `MCP_OAUTH_RESOURCE_NAME=Garmin Connect MCP`
5. Expose port `3000`.
6. Set the health check path to `/health`.
7. Attach your custom domain.

After deploy, verify:

```bash
curl https://your-domain.com/health
curl https://your-domain.com/
curl https://your-domain.com/.well-known/oauth-authorization-server
```

Then create the ChatGPT app in Developer Mode with the MCP endpoint URL:

```text
https://your-domain.com/mcp-your-secret-path
```

Authentication choice in ChatGPT:

- If `MCP_OAUTH_ENABLED=false`, choose `No Authentication`
- If `MCP_OAUTH_ENABLED=true`, choose `OAuth`

## Security Notes

This server uses one Garmin account configured through environment variables, so a remote deployment is effectively acting on behalf of that account.

- Anyone who can reach your MCP endpoint can use your Garmin tools.
- With OAuth enabled, anyone who knows your `MCP_OAUTH_USERNAME` and `MCP_OAUTH_PASSWORD` can authorize the connector.
- If you are deploying this only for yourself, use a private domain and a long unguessable `MCP_PATH`.
- If you need stronger access control, replace the built-in simple OAuth login with your own IdP or put the service behind an OAuth-capable gateway.
- OAuth clients, authorization codes, access tokens, and refresh tokens are stored in memory only. Restarting the service invalidates existing sessions and may require reauthorization in ChatGPT.

## Available Tools

### Activities (12 tools)
| Tool | Description |
|------|-------------|
| `get_activities` | List recent activities with pagination |
| `get_activities_by_date` | Search activities within a date range |
| `get_last_activity` | Get the most recent activity |
| `count_activities` | Get total number of activities |
| `get_activity` | Summary data for a specific activity |
| `get_activity_details` | Detailed metrics: HR, pace, elevation time series |
| `get_activity_splits` | Per-km or per-mile split data |
| `get_activity_weather` | Weather conditions during activity |
| `get_activity_hr_zones` | Time in each heart rate zone |
| `get_activity_exercise_sets` | Strength training sets (reps, weight) |
| `get_activity_types` | All available activity types |
| `get_progress_summary` | Fitness stats over a date range by activity type |

### Daily Health (14 tools)
| Tool | Description |
|------|-------------|
| `get_daily_summary` | Full daily summary (steps, calories, distance, etc.) |
| `get_steps` | Step count for a date |
| `get_steps_chart` | Intraday step data throughout the day |
| `get_heart_rate` | Heart rate data (resting, max, zones, time series) |
| `get_resting_heart_rate` | Resting heart rate for a date |
| `get_stress` | Stress levels and time series |
| `get_body_battery` | Body Battery energy levels (date range) |
| `get_body_battery_events` | Battery charge/drain events for a day |
| `get_respiration` | Breathing rate data |
| `get_spo2` | Blood oxygen saturation |
| `get_intensity_minutes` | Moderate/vigorous intensity minutes |
| `get_floors` | Floors climbed chart data |
| `get_hydration` | Daily hydration/water intake |
| `get_daily_events` | Daily wellness events |

### Trends (4 tools)
| Tool | Description |
|------|-------------|
| `get_daily_steps_range` | Daily step counts over a date range |
| `get_weekly_steps` | Weekly step aggregates |
| `get_weekly_stress` | Weekly stress aggregates |
| `get_weekly_intensity_minutes` | Weekly intensity minutes |

### Sleep (2 tools)
| Tool | Description |
|------|-------------|
| `get_sleep_data` | Sleep stages, score, bed/wake times |
| `get_sleep_data_raw` | Raw sleep data with HR and SpO2 |

### Body Composition (5 tools)
| Tool | Description |
|------|-------------|
| `get_body_composition` | Weight, BMI, body fat %, muscle mass (date range) |
| `get_latest_weight` | Most recent weight entry |
| `get_daily_weigh_ins` | All weigh-ins for a date |
| `get_weigh_ins` | Weigh-in records over a date range |
| `get_blood_pressure` | Blood pressure readings (date range) |

### Performance & Training (11 tools)
| Tool | Description |
|------|-------------|
| `get_vo2max` | VO2 Max estimate (running/cycling) |
| `get_training_readiness` | Training Readiness score |
| `get_training_status` | Training status and load |
| `get_hrv` | Heart Rate Variability |
| `get_endurance_score` | Endurance fitness score |
| `get_hill_score` | Climbing performance score |
| `get_race_predictions` | 5K/10K/half/full marathon predictions |
| `get_fitness_age` | Estimated fitness age |
| `get_personal_records` | All personal records |
| `get_lactate_threshold` | Lactate threshold HR and pace |
| `get_cycling_ftp` | Functional Threshold Power (cycling) |

### Profile & Devices (13 tools)
| Tool | Description |
|------|-------------|
| `get_user_profile` | User social profile and preferences |
| `get_user_settings` | User settings, measurement system, sleep schedule |
| `get_devices` | Registered Garmin devices |
| `get_device_settings` | Settings for a specific device |
| `get_device_last_used` | Last used device info |
| `get_primary_training_device` | Primary training device |
| `get_device_solar_data` | Solar charging data |
| `get_gear` | All tracked gear/equipment |
| `get_gear_stats` | Usage stats for a gear item |
| `get_goals` | Active goals and progress |
| `get_earned_badges` | Earned badges and achievements |
| `get_workouts` | Saved workouts |
| `get_workout` | Specific workout by ID |

## Authentication

Uses Garmin Connect credentials (email/password) via environment variables. OAuth tokens are cached in `~/.garmin-mcp/` to avoid re-authentication on each request.

### MFA (Multi-Factor Authentication)

If your Garmin account has MFA enabled (required for devices with ECG capabilities), you need to run the interactive setup once before using the MCP server:

```bash
GARMIN_EMAIL='you@email.com' GARMIN_PASSWORD='yourpass' npx -y @nicolasvegam/garmin-connect-mcp setup
```

This will:
1. Log in to Garmin Connect
2. Prompt you for the MFA code sent to your email or authenticator app
3. Save OAuth tokens to `~/.garmin-mcp/`

After setup, the MCP server will use the saved tokens automatically — no MFA prompt needed until the tokens expire. When they do, simply run the setup command again.

## Development

```bash
git clone https://github.com/Nicolasvegam/garmin-connect-mcp.git
cd garmin-connect-mcp
npm install
npm run build
```

To test locally on stdio:

```bash
GARMIN_EMAIL=you@email.com GARMIN_PASSWORD=yourpass npm start
```

To test locally on remote HTTP:

```bash
GARMIN_EMAIL=you@email.com GARMIN_PASSWORD=yourpass MCP_TRANSPORT=http PORT=3000 npm start
```

To test locally on remote HTTP with OAuth:

```bash
GARMIN_EMAIL=you@email.com \
GARMIN_PASSWORD=yourpass \
MCP_TRANSPORT=http \
PORT=3000 \
MCP_PATH=/mcp-local \
MCP_PUBLIC_BASE_URL=http://127.0.0.1:3000 \
MCP_OAUTH_ENABLED=true \
MCP_OAUTH_USERNAME=admin \
MCP_OAUTH_PASSWORD=secret \
npm start
```

## Credits

- API endpoints and authentication flow based on [`python-garminconnect`](https://github.com/cyberjunky/python-garminconnect) by [cyberjunky](https://github.com/cyberjunky)

## License

MIT
