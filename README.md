# ImmoScout24 Scraper Backend

A fully automated backend service for scraping and managing ImmoScout24 listings. Automatically searches for new properties, tracks listings, and sends contact messages based on your configured filters.

## Features

✅ **Automated Scraping** - Runs continuously in the background, checking for new listings every 5 minutes  
✅ **Session Management** - Maintains OAuth2 sessions with automatic token refresh  
✅ **Smart Filtering** - Only tracks NEW listings (filters out already seen properties)  
✅ **Auto-Contact** - Automatically sends contact messages to new listings  
✅ **Concurrent Processing** - Handles multiple accounts simultaneously  
✅ **Proxy Support** - Per-account proxy configuration  
✅ **Detailed Logging** - Daily rotating logs with 3-day retention  
✅ **REST API** - Monitor stats, trigger scrapes, download logs  

## Architecture

Just like `wg_backend`, this backend:
- Runs 24/7 with automated scheduling
- Uses Supabase for data storage
- Tracks which listings have been contacted
- Maintains session tokens with auto-refresh
- Processes multiple accounts concurrently

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env` and fill in your details:

```bash
cp .env.example .env
```

Edit `.env`:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key

# Optional: Proxy configuration
PROXY_URL=http://username:password@proxy.example.com:
```

### 3. Database Setup

Your Supabase `accounts` table should have these columns for ImmoScout24 accounts:

```sql
- id (UUID, primary key)
- website (TEXT) = 'immoscout24'
- email (TEXT) - account email
- password (TEXT) - account password
- session_details (JSONB) - OAuth tokens
- listing_data (JSONB) - tracked listings
- configuration (JSONB) - search filters & contact form
- last_updated_at (TIMESTAMPTZ) - last scrape time
```

### 4. Account Configuration

Create an account in Supabase with `website = 'immoscout24'` and configure these fields:

#### Configuration JSON Structure

```json
{
  "geocodes": "de/niedersachsen/celle-kreis/wienhausen",
  "pricetype": "rentpermonth",
  "proxy_port": 12531,
  "enteredFrom": "result_list",
  "livingspace": "2.0-20000.0",
  "contacted_ads": 0,
  "numberofrooms": "2.0-3000.0",
  "realestatetype": "apartmentrent",
  "scrape_enabled": true,
  "expose.contactForm": {
    "address": {
      "city": "Berlin",
      "street": "Hauptstr",
      "postcode": "10115",
      "houseNumber": "12"
    },
    "lastname": "Doe",
    "firstname": "John",
    "salutation": "MALE",
    "emailAddress": "john.doe@example.com",
    "message": "Hello, I'm interested in this property. Please send me more details."
  }
}
```

#### Configuration Parameters

**Search Filters:**
- `geocodes` - Location to search (e.g., "de/berlin/berlin")
- `realestatetype` - Property type ("apartmentrent", "assistedliving", etc.)
- `pricetype` - Price type (usually "rentpermonth")
- `livingspace` - Min-Max living space in m² (e.g., "2.0-20000.0")
- `numberofrooms` - Min-Max number of rooms (e.g., "2.0-3000.0")
- `enteredFrom` - Entry point ("result_list" or "one_step_search")

**Contact Form:**
- `expose.contactForm.address` - Your address details
- `expose.contactForm.firstname` / `lastname` - Your name
- `expose.contactForm.salutation` - Gender ("MALE" or "FEMALE")
- `expose.contactForm.emailAddress` - Your email
- `expose.contactForm.message` - Message to send (optional)

**Other:**
- `scrape_enabled` - Enable/disable scraping for this account (boolean)
- `proxy_port` - Proxy port to use (optional)
- `contacted_ads` - Counter of contacted listings (auto-updated)

#### Session Details JSON Structure

The session is created by your frontend login flow. Example:

```json
{
  "id_token": "eyJraWQiOiJWSTctS2xfMTdSZkc5...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "access_token": "eyJraWQiOiJWSTctS2xfMTdSZkc5...",
  "refresh_token": "ifCJIskM1ET96hgb-D3Tr6cQXeX...",
  "session_created_at": "2025-10-29T21:22:05.184723"
}
```

**Note:** The backend automatically refreshes tokens when they're older than 50 minutes (tokens expire at 60 minutes).

## Running the Backend

### Development Mode

```bash
python app.py
```

The server will start on `http://0.0.0.0:5002`

### Production Mode

Use a process manager like `pm2`:

```bash
pm2 start app.py --name immo24-scraper --interpreter python3
```

Or use `systemd` service:

```ini
[Unit]
Description=ImmoScout24 Scraper Backend
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/immo24_backend
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## API Endpoints

### `GET /`
Health check - returns service status

**Response:**
```json
{
  "status": "running",
  "service": "ImmoScout24 Scraper Backend",
  "version": "1.0.0"
}
```

### `GET /stats`
Get scraper statistics and configuration

**Response:**
```json
{
  "stats": {
    "total_runs": 42,
    "successful_runs": 40,
    "failed_runs": 2,
    "total_new_offers": 15,
    "last_check": "2025-10-29T15:30:00",
    "currently_running": 0,
    "accounts_processed": [...]
  },
  "config": {
    "scraper_interval_minutes": 5,
    "queue_check_interval_minutes": 2,
    "max_concurrent_scrapers": 10
  }
}
```

### `GET /accounts`
List all ImmoScout24 accounts

**Response:**
```json
{
  "success": true,
  "count": 2,
  "accounts": [
    {
      "id": "uuid-here",
      "email": "user@example.com",
      "website": "immoscout24",
      "last_updated_at": "2025-10-29T15:25:00",
      "configuration": {...}
    }
  ]
}
```

### `GET /accounts/ready`
List accounts ready to be scraped (haven't been updated in SCRAPER_INTERVAL minutes and have scrape_enabled = true)

**Response:**
```json
{
  "success": true,
  "count": 1,
  "accounts": [
    {
      "id": "uuid-here",
      "email": "user@example.com",
      "last_updated_at": "2025-10-29T15:20:00",
      "scrape_enabled": true
    }
  ]
}
```

### `POST /scrape/trigger`
Manually trigger a scrape check (useful for testing)

**Response:**
```json
{
  "success": true,
  "message": "Triggered scraping for 1 accounts",
  "count": 1
}
```

### `GET /logs`
List all available log files

**Response:**
```json
{
  "success": true,
  "count": 3,
  "logs": [
    {
      "filename": "scraper.log",
      "size_bytes": 45632,
      "size_mb": 0.04,
      "modified": "2025-10-29T15:30:00",
      "download_url": "/logs/download/scraper.log"
    }
  ]
}
```

### `GET /logs/download` or `GET /logs/download/<filename>`
Download a log file

**Response:** Plain text log file

## How It Works

### 1. Background Scheduler
- Runs in a separate thread
- Checks every 2 minutes for accounts ready to scrape
- An account is ready if:
  - `website = 'immoscout24'`
  - `configuration.scrape_enabled = true`
  - Last update was > 5 minutes ago (or never updated)

### 2. Scraping Process
For each ready account:
1. **Validate Session** - Check if OAuth token is valid, refresh if needed
2. **Search Listings** - Fetch listings using configured filters
3. **Filter New Listings** - Only keep listings newer than `listing_data.last_latest`
4. **Update Database** - Save new listings and update `last_latest` timestamp
5. **Auto-Contact** - Send contact messages to new listings
6. **Update Counter** - Increment `contacted_ads` counter

### 3. Session Management
- OAuth2 tokens expire after 60 minutes
- Backend proactively refreshes tokens at 50 minutes
- Refresh tokens are long-lived and stored in `session_details`
- If refresh fails, frontend must create a new session

### 4. Listing Tracking
- `listing_data.last_latest` stores the timestamp of the newest seen listing
- On each run, only listings NEWER than this timestamp are saved
- This prevents duplicate contacts and keeps data fresh

## Configuration Examples

### Basic Apartment Search in Berlin

```json
{
  "geocodes": "de/berlin/berlin",
  "realestatetype": "apartmentrent",
  "pricetype": "rentpermonth",
  "livingspace": "40.0-80.0",
  "numberofrooms": "2.0-3.0",
  "scrape_enabled": true,
  "expose.contactForm": {
    "address": {
      "city": "Berlin",
      "street": "Musterstr",
      "postcode": "10115",
      "houseNumber": "1"
    },
    "firstname": "John",
    "lastname": "Doe",
    "salutation": "MALE",
    "emailAddress": "john@example.com"
  }
}
```

### With Proxy and Custom Message

```json
{
  "geocodes": "de/niedersachsen/hannover",
  "realestatetype": "apartmentrent",
  "pricetype": "rentpermonth",
  "proxy_port": 12531,
  "scrape_enabled": true,
  "expose.contactForm": {
    "address": {
      "city": "Hannover",
      "street": "Bahnhofstr",
      "postcode": "30159",
      "houseNumber": "5"
    },
    "firstname": "Jane",
    "lastname": "Smith",
    "salutation": "FEMALE",
    "emailAddress": "jane@example.com",
    "message": "Hello! I'm very interested in this apartment. I'm a working professional looking for long-term rental. Could you please send me more information?"
  }
}
```

## Troubleshooting

### Backend won't start
- Check `.env` file exists and has correct Supabase credentials
- Verify Python dependencies are installed: `pip install -r requirements.txt`

### No listings found
- Verify `scrape_enabled = true` in account configuration
- Check if session is valid (should auto-refresh)
- Ensure search filters aren't too restrictive

### Session expired errors
- Backend should auto-refresh tokens
- If refresh fails, create a new session from frontend
- Check that `session_details` contains valid `refresh_token`

### Auto-contact not working
- Verify `expose.contactForm` exists in configuration
- Check that all required fields are filled (address, name, email, salutation)
- Look at logs for specific error messages

## Logs

Logs are stored in `logs/scraper.log` with automatic daily rotation:
- Current log: `logs/scraper.log`
- Rotated logs: `logs/scraper.log.2025-10-29`, etc.
- Retention: 3 days (older logs are automatically deleted)

Download logs via API: `GET http://localhost:5002/logs/download`

## Comparison with WG Backend

| Feature | WG Backend | Immo24 Backend |
|---------|-----------|----------------|
| Port | 5001 | 5002 |
| Website | wg-gesucht | immoscout24 |
| Auth | Session-based | OAuth2 + PKCE |
| Token Refresh | 40 min | 50 min |
| Auto-Contact | ✅ | ✅ |
| Proxy Support | ✅ | ✅ |
| Scheduling | ✅ | ✅ |
| Concurrent Scraping | ✅ | ✅ |

## License

MIT
