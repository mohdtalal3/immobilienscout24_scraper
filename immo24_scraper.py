import os
import re
import json
import time
import uuid
import base64
import hashlib
import requests
from datetime import datetime, timedelta
from supabase import Client
from logger_config import setup_logger
import random
# Setup logger
logger = setup_logger('immo24_scraper')


# ===================================================
# JWT DECODE HELPER
# ===================================================
def decode_jwt(token: str) -> dict:
    """
    Decode JWT token to extract payload (e.g., ssoId).
    Does not verify signature - only decodes the payload.
    """
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception as e:
        logger.error(f"❌ Error decoding JWT: {e}")
        return {}


class Immo24Client:
    """ImmoScout24 API Client with OAuth2 login, session management, and listing scraping."""
    
    # OAuth2 Configuration
    CLIENT_ID = "is24-android-de"
    SERVER_ID = "aus1227au6oBg6hGH417"
    REDIRECT_URI = "immobilienscout24.de:/loginCallback"
    SCOPE = "openid profile offline_access"
    USER_AGENT = "okta-oauth2-kotlin/2.0.3 Android/34"
    
    AUTHN_URL = "https://login.immobilienscout24.de/api/v1/authn"
    AUTHORIZE_URL = f"https://login.immobilienscout24.de/oauth2/{SERVER_ID}/v1/authorize"
    TOKEN_URL = f"https://login.immobilienscout24.de/oauth2/{SERVER_ID}/v1/token"
    
    # API Configuration
    SEARCH_API_URL = "https://api.mobile.immobilienscout24.de/search/list"
    CONTACT_API_URL = "https://api.mobile.immobilienscout24.de/expose/{}/contact"
    
    API_USER_AGENT = "ImmoScout24_1458_34_._"
    #API_CLIENT_ID = "2914dca0b3cf4271950abd8a7a01d87e"

    def __init__(self, proxy_url: str = None):
        self.access_token = None
        self.refresh_token = None
        self.id_token = None
        self.expires_in = None
        self.token_type = None
        
        # Setup proxy if provided
        self.proxies = None
        if proxy_url:
            self.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            logger.info(f"🔒 Proxy configured: {proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url}")

    # ---------------------------------------------------
    # PKCE Helper Functions
    # ---------------------------------------------------
    @staticmethod
    def make_pkce_pair():
        """Generate PKCE code_verifier and code_challenge."""
        code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode("utf-8")
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("utf-8")).digest()
        ).rstrip(b"=").decode("utf-8")
        return code_verifier, code_challenge

    # ---------------------------------------------------
    # Login Flow
    # ---------------------------------------------------
    def get_session_token(self, email: str, password: str, otp: str = None) -> str:
        """
        Get session token via email/password authentication.
        Handles MFA if otp is provided.
        """
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": self.USER_AGENT
        }
        payload = {
            "username": email,
            "password": password,
            "options": {"multiOptionalFactorEnroll": False, "warnBeforePasswordExpired": False}
        }

        logger.info(f"🔐 Authenticating {email}...")
        r = requests.post(self.AUTHN_URL, headers=headers, json=payload, proxies=self.proxies, timeout=20)
        j = r.json()

        # Success case
        if j.get("status") == "SUCCESS":
            logger.info(f"✅ Session token obtained for {email}")
            return j["sessionToken"]

        # MFA required
        if j.get("status") == "MFA_REQUIRED":
            if not otp:
                logger.error(f"❌ MFA required for {email} but no OTP provided")
                raise Exception("MFA required but no OTP provided")
            
            factor = j["_embedded"]["factors"][0]
            verify_url = factor["_links"]["verify"]["href"]
            state_token = j["stateToken"]
            
            logger.info(f"🔐 Verifying MFA code for {email}...")
            verify = requests.post(
                verify_url,
                headers=headers,
                json={"stateToken": state_token, "passCode": otp},
                proxies=self.proxies,
                timeout=20
            )
            j2 = verify.json()

            if j2.get("status") != "SUCCESS":
                logger.error(f"❌ MFA verification failed for {email}")
                raise Exception("MFA verification failed")
            
            logger.info(f"✅ MFA verified for {email}")
            return j2["sessionToken"]

        raise Exception(f"Login failed for {email}: {j}")

    def get_authorization_code(self, session_token: str, code_challenge: str) -> str:
        """Get authorization code using session token."""
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        params = {
            "source": "myaccount",
            "utm_medium": "app",
            "utm_source": "android",
            "utm_campaign": "sso_entrance",
            "app_name": self.CLIENT_ID,
            "consent": "true",
            #"androidTestingId": "34471d6f8a4ffeac1c684833e3e68c24",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "client_id": self.CLIENT_ID,
            "scope": self.SCOPE,
            "redirect_uri": self.REDIRECT_URI,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "sessionToken": session_token,
            "prompt": "none"
        }
        headers = {"user-agent": self.USER_AGENT, "accept": "application/json"}
        
        logger.info("🌐 Requesting authorization code...")
        r = requests.get(
            self.AUTHORIZE_URL, 
            params=params, 
            headers=headers, 
            allow_redirects=False, 
            proxies=self.proxies,
            timeout=20
        )
        
        if "Location" not in r.headers:
            logger.error("❌ No Location header in authorize response")
            raise Exception("No Location header – invalid authorize response.")
        
        loc = r.headers["Location"]
        m = re.search(r"[?&]code=([^&]+)", loc)
        if not m:
            logger.error(f"❌ Code not found in redirect URL: {loc}")
            raise Exception("Code not found in redirect URL")
        
        code = m.group(1)
        logger.info("✅ Authorization code obtained")
        return code

    def exchange_code_for_tokens(self, code: str, code_verifier: str) -> dict:
        """Exchange authorization code for access/refresh tokens."""
        logger.info("💬 Exchanging code for tokens...")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.REDIRECT_URI,
            "client_id": self.CLIENT_ID,
            "code_verifier": code_verifier
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": self.USER_AGENT
        }
        r = requests.post(self.TOKEN_URL, data=data, headers=headers, proxies=self.proxies, timeout=20)
        
        if r.status_code != 200:
            logger.error(f"❌ Token exchange failed: {r.text[:500]}")
            raise Exception("Token exchange failed")
        
        tokens = r.json()
        self._set_tokens(tokens)
        logger.info("✅ Tokens obtained successfully")
        return tokens

    def _set_tokens(self, tokens: dict):
        """Set tokens from response."""
        self.access_token = tokens.get('access_token')
        self.refresh_token = tokens.get('refresh_token')
        self.id_token = tokens.get('id_token')
        self.expires_in = tokens.get('expires_in')
        self.token_type = tokens.get('token_type', 'Bearer')

    def login(self, email: str, password: str, otp: str = None) -> bool:
        """
        Complete login flow: get session token, authorize, and exchange for tokens.
        Returns True on success.
        """
        try:
            session_token = self.get_session_token(email, password, otp)
            code_verifier, code_challenge = self.make_pkce_pair()
            code = self.get_authorization_code(session_token, code_challenge)
            self.exchange_code_for_tokens(code, code_verifier)
            logger.info(f"✅ Login successful for {email}")
            return True
        except Exception as e:
            logger.error(f"❌ Login failed for {email}: {e}")
            return False

    # ---------------------------------------------------
    # Token Refresh
    # ---------------------------------------------------
    def refresh_session(self) -> bool:
        """Refresh access token using refresh token."""
        if not self.refresh_token:
            logger.warning("⚠️ No refresh token available")
            return False
        
        logger.info("♻️ Refreshing tokens...")
        data = {
            "grant_type": "refresh_token",
            "client_id": self.CLIENT_ID,
            "refresh_token": self.refresh_token
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": self.USER_AGENT
        }
        
        r = requests.post(self.TOKEN_URL, data=data, headers=headers, proxies=self.proxies, timeout=20)
        
        if r.status_code != 200:
            logger.error(f"❌ Token refresh failed: {r.text}")
            return False
        
        tokens = r.json()
        self._set_tokens(tokens)
        logger.info("✅ Tokens refreshed successfully")
        return True

    # ---------------------------------------------------
    # Session Management
    # ---------------------------------------------------
    def get_session_dict(self) -> dict:
        """Return session details as a dictionary for storage with timestamp."""
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'id_token': self.id_token,
            'expires_in': self.expires_in,
            'token_type': self.token_type,
            'session_created_at': datetime.now().isoformat()
        }

    def set_session_from_dict(self, session_data: dict):
        """Load session from a dictionary."""
        self.access_token = session_data.get('access_token')
        self.refresh_token = session_data.get('refresh_token')
        self.id_token = session_data.get('id_token')
        self.expires_in = session_data.get('expires_in')
        self.token_type = session_data.get('token_type', 'Bearer')

    # ---------------------------------------------------
    # Listing Search
    # ---------------------------------------------------
    @staticmethod
    def parse_published_time(text):
        """
        Converts relative time strings like:
        'a minute ago', '2 hours ago', '14 days ago', '3 weeks ago',
        '2 months ago', 'yesterday', '10 seconds ago' → datetime object.
        Never crashes, returns None only if text is empty.
        """
        if not text:
            return None

        text = text.lower().strip()
     #   print("Parsing published time text:", text)
        now = datetime.now()

        try:
            # --- Explicit "a"/"an" forms ---
            if text in ["a second ago", "a minute ago", "an minute ago"]:
                return now - timedelta(seconds=60)
            elif text in ["a hour ago", "an hour ago"]:
                return now - timedelta(hours=1)
            elif text == "yesterday":
                return now - timedelta(days=1)

            # --- Numeric forms ---
            match = re.search(r"(\d+)", text)
            if match:
                n = int(match.group(1))
                if "second" in text:
                    return now - timedelta(seconds=n)
                elif "minute" in text:
                    return now - timedelta(minutes=n)
                elif "hour" in text:
                    return now - timedelta(hours=n)
                elif "day" in text:
                    return now - timedelta(days=n)
                elif "week" in text:
                    return now - timedelta(weeks=n)
                elif "month" in text:
                    return now - timedelta(days=n * 30)
                elif "year" in text:
                    return now - timedelta(days=n * 365)

            # --- Absolute formats (e.g., '29 Oct 2025') ---
            try:
                return datetime.strptime(text, "%d %b %Y")
            except Exception:
                pass

            # --- Fallback: return current time if not matched ---
            return False

        except Exception as e:
            print("⚠️ parse_published_time error:", e)
            return False



    def search_listings(self, config: dict) -> list:
        """
        Search for listings using configuration parameters.
        
        Dynamically loads all config parameters as filters, excluding:
        - proxy_port (system setting)
        - contacted_ads (counter)
        - scrape_enabled (system flag)
        - expose.contactForm (contact data)
        
        All other key-value pairs from config are added as search filters.
        """
        if not self.access_token:
            logger.error("❌ Not authenticated - cannot search listings")
            return []
        
        search_id = str(uuid.uuid4())
        
        # Fields to exclude from search parameters (system/internal use only)
        EXCLUDED_FIELDS = {
            'proxy_port',
            'contacted_ads',
            'scrape_enabled',
            'expose.contactForm'
        }
        
        # Start with required base parameters
        params = {
            "searchType": "region",
            "features": "adKeysAndStringValues",
            "searchid": search_id,
            "sorting": "-firstactivation",
            "pagesize": "49",
            "pagenumber": "1"
        }
        
        # Dynamically add all config parameters as filters (except excluded ones)
        for key, value in config.items():
            if key not in EXCLUDED_FIELDS and value is not None:
                params[key] = str(value) if not isinstance(value, str) else value
        
        data = {
            "supportedResultListTypes": [
                "ADVERTISEMENT",
                "LIST_FIRST_LISTING_BANNER",
                "REALTOR_TOUCHPOINT",
                "SURROUNDINGS"
            ],
            "userData": {}
        }
        #print(params)
        headers = {
            "User-Agent": self.API_USER_AGENT,
            "Accept": "application/json",
            "Accept-Language": "en",
            #"x_is24_client_id": self.API_CLIENT_ID,
            "x-is24-feature": "presale",
            "Content-Type": "application/json",
            #"Authorization": f"Bearer {self.access_token}",
            "Accept-Encoding": "gzip"
        }
        
        # Log applied filters
        filter_summary = []
        for key, value in params.items():
            if key not in ['searchType', 'features', 'searchid', 'sorting', 'pagesize', 'pagenumber']:
                filter_summary.append(f"{key}={value}")
        logger.info(f"🔍 Searching listings with filters: {', '.join(filter_summary) if filter_summary else 'none'}")
        
        try:
            response = requests.post(
                self.SEARCH_API_URL,
                params=params,
                headers=headers,
                json=data,
                proxies=self.proxies,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"❌ Search request failed: {response.status_code}")
                return []
            
            data_json = response.json()
            result_list = data_json.get("resultListItems", [])
            
            extracted = []
            skipped_paywall = 0
            
            for item in result_list:
                if item.get("type") != "EXPOSE_RESULT":
                    continue
                
                ad = item.get("item", {})
                
                # Skip listings that require Plus subscription
                # Check if paywallListing exists and is active
                paywall_listing = ad.get("paywallListing", {})
                if paywall_listing and paywall_listing.get("active"):
                    skipped_paywall += 1
                    continue
                
                # Also check tags for paywall tag
                tags = ad.get("tags", [])
                has_paywall_tag = any(tag.get("tag") == "paywall" for tag in tags)
                if has_paywall_tag:
                    skipped_paywall += 1
                    continue
                
                published_dt = self.parse_published_time(ad.get("published", ""))
                # If we can't parse, skip or mark as unknown
                if not published_dt:
                    continue  # or set to now if you prefer: published_dt = datetime.now()
                extracted.append({
                    "id": ad.get("id"),
                    "title": ad.get("title"),
                    "published": published_dt.isoformat(timespec="seconds"),
                    "url": f"https://www.immobilienscout24.de/expose/{ad.get('id')}"
                })
            
            # Sort by published datetime (latest first)
            extracted.sort(key=lambda x: datetime.fromisoformat(x["published"]), reverse=True)
            
            if skipped_paywall > 0:
                logger.info(f"🚫 Skipped {skipped_paywall} Plus subscription listings")
            logger.info(f"✅ Found {len(extracted)} contactable listings")
            return extracted
            
        except Exception as e:
            logger.error(f"❌ Error searching listings: {e}")
            return []

    # ---------------------------------------------------
    # Contact Listing
    # ---------------------------------------------------
    def contact_listing(self, expose_id: str, contact_form: dict) -> bool:
        """
        Send a contact message to a listing.
        
        Automatically extracts ssoId from id_token.
        
        contact_form should contain:
        - address: {street, houseNumber, postcode, city}
        - emailAddress
        - firstname
        - lastname
        - salutation (e.g., "MALE" or "FEMALE")
        - message (optional, will use default if not provided)
        """
        if not self.access_token:
            logger.error("❌ Not authenticated - cannot contact listing")
            return False
        
        # Extract ssoId from id_token
        sso_id = None
        print(sso_id)
        if self.id_token:
            decoded = decode_jwt(self.id_token)
            sso_id = decoded.get("ssoId")
            if sso_id:
                logger.info(f"✅ Extracted ssoId from id_token: {sso_id}")
            else:
                logger.warning("⚠️ No ssoId found in id_token")
        else:
            logger.warning("⚠️ No id_token available")
        
        url = self.CONTACT_API_URL.format(expose_id)
        params = {"referrer": "resultlist"}
        
        headers = {
            "Host": "api.mobile.immobilienscout24.de",
            "User-Agent": self.API_USER_AGENT,
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; charset=UTF-8",
            "Accept-Encoding": "gzip"
        }
        
        # Build payload
        payload = {
            "expose.contactForm": {
                "address": contact_form.get("address", {}),
                "emailAddress": contact_form.get("emailAddress"),
                "firstname": contact_form.get("firstname"),
                "lastname": contact_form.get("lastname"),
                "salutation": contact_form.get("salutation", "MALE"),
                "privacyPolicyAccepted": True,
                "profileType": "BASIC",
                "sendProfile": True
            },
            "supportedScreens": ["registration", "valuation"],
            "requestCount": 1,
            "doNotSend": False,
            "entitlements": []
        }
        
        # Add optional fields from contact_form
        if "message" in contact_form:
            payload["expose.contactForm"]["message"] = contact_form["message"]
        # if "moveInDate" in contact_form:
        #     payload["expose.contactForm"]["moveInDate"] = contact_form["moveInDate"]
        # if "employmentRelationship" in contact_form:
        #     payload["expose.contactForm"]["employmentRelationship"] = contact_form["employmentRelationship"]
        
        # Add ssoId if extracted from id_token
        if sso_id:
            payload["ssoId"] = sso_id
        
        logger.info(f"📤 Contacting listing {expose_id}...")
        
        try:
            response = requests.post(
                url,
                headers=headers,
                params=params,
                data=json.dumps(payload),
                proxies=self.proxies,
                timeout=30
            )
            
            if response.status_code in [200, 201, 500]:
                # 200/201 = Successfully contacted
                # 500 = Also means successfully contacted (API quirk)
                logger.info(f"✅ Successfully contacted listing {expose_id}")
                return True
            # elif response.status_code in [400, 403, 404, 409]:
            #     # Common errors that shouldn't stop the scraper:
            #     # 400 = Bad Request (already contacted, invalid data)
            #     # 403 = Forbidden (already contacted, rate limit)
            #     # 404 = Not Found (listing removed)
            #     # 409 = Conflict (already contacted)
            #     logger.warning(f"⚠️ Could not contact listing {expose_id}: {response.status_code}")
            #     logger.warning(f"   Response: {response.text[:500]}")
            #     return True  # Continue anyway
            else:
                logger.error(f"❌ Failed to contact listing {expose_id}: {response.status_code}")
                logger.error(f"   Response: {response.text[:500]}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error contacting listing {expose_id}: {e}")
            return False


# ===================================================
# UTILITY FUNCTIONS
# ===================================================

def ensure_valid_session(client: Immo24Client, account: dict, supabase: Client) -> bool:
    """
    Ensures the client has a valid session for authenticated requests.
    Checks session age - if older than 50 minutes (tokens valid for 60 min), proactively refreshes.
    
    Returns True if session is valid/refreshed, False if no session or login failed.
    """
    session_details = account.get('session_details')
    
    # No session at all - skip (session must be created from frontend)
    if not session_details:
        logger.warning(f"⚠️ [{account['email']}] No session found. Session must be created from frontend first.")
        return False
    
    # Load existing session
    client.set_session_from_dict(session_details)
    
    # Check session age (tokens valid for 60 min, refresh at 50 min)
    session_created_str = session_details.get('session_created_at')
    
    if session_created_str:
        try:
            session_created = datetime.fromisoformat(session_created_str)
            age_minutes = (datetime.now() - session_created).total_seconds() / 60
            
            logger.info(f"🕐 [{account['email']}] Session age: {age_minutes:.1f} minutes")
            
            # If session is older than 50 minutes, refresh it proactively
            if age_minutes > 50:
                logger.warning(f"⚠️ [{account['email']}] Session older than 50 minutes. Refreshing token...")
                
                if not client.refresh_session():
                    logger.error(f"❌ [{account['email']}] Token refresh failed. Re-login required from frontend.")
                    
                    # Automatically disable account to prevent repeated failures
                    config = account.get('configuration', {})
                    config['scrape_enabled'] = False
                    supabase.table('accounts').update({
                        'configuration': config
                    }).eq('id', account['id']).execute()
                    logger.error(f"🔴 [{account['email']}] Auto-disabled account (scrape_enabled=false). Please re-login from frontend.")
                    
                    return False
                
                # Update session in database
                new_session = client.get_session_dict()
                supabase.table('accounts').update({
                    'session_details': new_session
                }).eq('id', account['id']).execute()
                logger.info(f"✅ [{account['email']}] Session refreshed and updated.")
                return True
            else:
                logger.info(f"✅ [{account['email']}] Session is fresh (expires in ~{60 - age_minutes:.0f} minutes).")
                return True
                
        except Exception as e:
            logger.warning(f"⚠️ [{account['email']}] Could not parse session timestamp: {e}")
    
    # If no timestamp or parsing failed, try to refresh
    logger.warning(f"⚠️ [{account['email']}] No valid session timestamp. Attempting token refresh...")
    if client.refresh_session():
        new_session = client.get_session_dict()
        supabase.table('accounts').update({
            'session_details': new_session
        }).eq('id', account['id']).execute()
        logger.info(f"✅ [{account['email']}] Token refreshed and session updated.")
        return True
    
    logger.error(f"❌ [{account['email']}] Token refresh failed. Re-login required from frontend.")
    
    # Automatically disable account to prevent repeated failures
    config = account.get('configuration', {})
    config['scrape_enabled'] = False
    supabase.table('accounts').update({
        'configuration': config
    }).eq('id', account['id']).execute()
    logger.error(f"🔴 [{account['email']}] Auto-disabled account (scrape_enabled=false). Please re-login from frontend.")
    
    return False


# ===================================================
# MAIN SCRAPER FUNCTION
# ===================================================

def run_scraper_for_account(account: dict, supabase: Client):
    """
    Run scraper for a single ImmoScout24 account from Supabase.
    
    - Uses existing session or refreshes if needed
    - Searches for new listings based on configuration
    - Filters ONLY offers newer than 'last_latest'
    - FULLY REPLACES listing_data with new filtered offers
    - Updates 'last_latest' to newest timestamp
    - AUTO-CONTACTS new offers if contact form is configured
    - Updates 'last_updated_at' timestamp
    
    Returns: (success: bool, new_offers_count: int)
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"🏃 Running scraper for: {account['email']}")
    logger.info(f"{'='*60}")
    
    # Get configuration from account
    config = account.get('configuration', {})
    proxy_port = config.get('proxy_port')
    
    # Build proxy URL if proxy_port is provided
    proxy_url = None
    if proxy_port:
        proxy_base = os.getenv('PROXY_URL')
        if proxy_base:
            proxy_url = f"{proxy_base}{proxy_port}"
            logger.info(f"🔒 [{account['email']}] Using proxy port: {proxy_port}")
        else:
            logger.warning(f"⚠️ [{account['email']}] PROXY_URL not found in environment, running without proxy")
    else:
        logger.info(f"ℹ️ [{account['email']}] No proxy port configured, running without proxy")
    
    # Initialize client with proxy
    client = Immo24Client(proxy_url=proxy_url)
    
    # Ensure valid session before scraping
    logger.info(f"🔐 [{account['email']}] Validating session...")
    if not ensure_valid_session(client, account, supabase):
        logger.error(f"❌ [{account['email']}] Could not establish valid session. Cannot fetch listings.")
        return False, 0
    
    # Search for listings
    logger.info(f"🔍 [{account['email']}] Fetching listings...")
    listings = client.search_listings(config)
    
    if not listings:
        logger.warning(f"⚠️ [{account['email']}] No listings found or request failed.")
        # Still update last_updated_at
        supabase.table('accounts').update({
            'last_updated_at': datetime.now().isoformat()
        }).eq('id', account['id']).execute()
        return True, 0
    
    logger.info(f"✅ [{account['email']}] Fetched {len(listings)} listings.")
    
    # Load existing listing_data to get previous last_latest
    existing_listing_data = account.get('listing_data', {}) or {}
    last_latest_str = existing_listing_data.get('last_latest')
    last_latest_time = datetime.fromisoformat(last_latest_str) if last_latest_str else None
    
    # Extract latest timestamp from fetched listings
    latest_time_in_fetch = max(
        [datetime.fromisoformat(l['published']) for l in listings],
        default=None
    )
    
    # First run: initialize
    if not last_latest_time:
        latest_str = latest_time_in_fetch.isoformat(timespec="seconds") if latest_time_in_fetch else None
        new_listing_data = {
            "last_latest": latest_str,
            "offers": []
        }
        
        supabase.table('accounts').update({
            'listing_data': new_listing_data,
            'last_updated_at': datetime.now().isoformat()
        }).eq('id', account['id']).execute()
        
        logger.info(f"🆕 [{account['email']}] Initialized listing_data with last_latest: {latest_str}")
        logger.info(f"    Next run will save only newer listings.")
        return True, 0
    
    # Subsequent runs: filter only listings newer than last_latest
    logger.info(f"📌 [{account['email']}] Previous last_latest: {last_latest_str}")
    
    new_offers = []
    for listing in listings:
        listing_time = datetime.fromisoformat(listing['published'])
        
        if listing_time > last_latest_time:
            new_offers.append(listing)
    
    if not new_offers:
        logger.info(f"✅ [{account['email']}] No new listings found — everything is up to date.")
        # Still update last_updated_at
        supabase.table('accounts').update({
            'last_updated_at': datetime.now().isoformat()
        }).eq('id', account['id']).execute()
        return True, 0
    
    # Update "last_latest" to the newest time found in new offers
    newest_time = max(datetime.fromisoformat(o['published']) for o in new_offers)
    newest_str = newest_time.isoformat(timespec="seconds")
    
    # Sort new offers by date descending
    new_offers = sorted(
        new_offers,
        key=lambda x: datetime.fromisoformat(x['published']),
        reverse=True
    )
    
    # FULLY REPLACE listing_data with ONLY new filtered listings
    updated_listing_data = {
        "last_latest": newest_str,
        "offers": new_offers
    }
    
    # Save to Supabase first
    try:
        supabase.table('accounts').update({
            'listing_data': updated_listing_data,
            'last_updated_at': datetime.now().isoformat()
        }).eq('id', account['id']).execute()
        
        logger.info(f"🆕 [{account['email']}] Added {len(new_offers)} new offers.")
        logger.info(f"📅 [{account['email']}] Updated last_latest → {newest_str}")
        
    except Exception as e:
        logger.error(f"❌ [{account['email']}] Error saving to Supabase: {e}")
        return False, 0
    
    # ===================================================
    # AUTO-CONTACT NEW OFFERS
    # ===================================================
    
    # Get contact form from configuration
    contact_form = config.get('expose.contactForm')
    
    if not contact_form:
        logger.warning(f"⚠️ [{account['email']}] No contact form found in configuration. Skipping auto-contact.")
        return True, len(new_offers)
    
    # Get message from the SEPARATE 'message' field in Supabase (not in configuration)
    contact_message = account.get('message')
    if not contact_message or not contact_message.strip():
        logger.warning(f"⚠️ [{account['email']}] No message found in 'message' field. Skipping auto-contact.")
        return True, len(new_offers)
    
    # Add the message to contact form
    contact_form['message'] = contact_message
    logger.info(f"📝 [{account['email']}] Using message from separate 'message' field: {contact_message[:50]}...")
    
    # Load contacted IDs history (last 50) to prevent duplicates
    contacted_ids_history = existing_listing_data.get('contacted_ids', [])
    if not isinstance(contacted_ids_history, list):
        contacted_ids_history = []
    
    logger.info(f"📋 [{account['email']}] Loaded {len(contacted_ids_history)} previously contacted IDs from history")
    
    # Session was already validated above before searching, no need to check again
    logger.info(f"💬 [{account['email']}] Auto-contacting {len(new_offers)} new offers...")
    
    # Contact each offer
    contacted_count = 0
    failed_count = 0
    skipped_count = 0
    newly_contacted_ids = []
    
    for offer in new_offers:
        offer_id = offer.get('id')
        offer_title = offer.get('title', 'Unknown')
        offer_url = offer.get('url', '')
        
        # Check if already contacted (duplicate detection)
        if offer_id in contacted_ids_history:
            skipped_count += 1
            logger.info(f"⏭️  [{account['email']}] Skipping offer {offer_id} (already contacted): {offer_title[:40]}...")
            continue
        
        logger.info(f"📤 [{account['email']}] Contacting offer {offer_id}: {offer_title[:40]}...")
        logger.info(f"   🔗 URL: {offer_url}")
        
        result = client.contact_listing(str(offer_id), contact_form)
        
        if result:
            contacted_count += 1
            newly_contacted_ids.append(offer_id)
            logger.info(f"   ✅ [{account['email']}] Successfully contacted offer {offer_id}")
        else:
            failed_count += 1
            logger.error(f"   ❌ [{account['email']}] Failed to contact offer {offer_id}")
        time.sleep(random.uniform(1, 2))
    
    # Update contacted_ids history (keep last 50)
    if newly_contacted_ids:
        # Merge new IDs with existing history
        updated_contacted_ids = newly_contacted_ids + contacted_ids_history
        # Keep only last 50 IDs
        updated_contacted_ids = updated_contacted_ids[:50]
        
        # Update listing_data with new contacted_ids history
        updated_listing_data['contacted_ids'] = updated_contacted_ids
        
        try:
            supabase.table('accounts').update({
                'listing_data': updated_listing_data
            }).eq('id', account['id']).execute()
            
            logger.info(f"💾 [{account['email']}] Updated contacted_ids history: {len(updated_contacted_ids)} IDs stored")
        except Exception as e:
            logger.error(f"❌ [{account['email']}] Error updating contacted_ids history: {e}")
    
    # Update the contacted_ads counter in configuration
    if contacted_count > 0:
        try:
            current_contacted = config.get('contacted_ads', 0)
            new_total = current_contacted + contacted_count
            
            config['contacted_ads'] = new_total
            
            supabase.table('accounts').update({
                'configuration': config
            }).eq('id', account['id']).execute()
            
            logger.info(f"📈 [{account['email']}] Updated contacted_ads: {current_contacted} → {new_total}")
        except Exception as e:
            logger.error(f"❌ [{account['email']}] Error updating contacted_ads counter: {e}")
    
    if skipped_count > 0:
        logger.info(f"📊 [{account['email']}] Contact Summary: ✅ {contacted_count} | ❌ {failed_count} | ⏭️  {skipped_count} skipped (duplicates)")
    else:
        logger.info(f"📊 [{account['email']}] Contact Summary: ✅ {contacted_count} | ❌ {failed_count}")
    
    logger.info(f"✅ [{account['email']}] Scraper completed successfully!")
    
    return True, len(new_offers)
