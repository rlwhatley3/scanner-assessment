"""Thin wrapper around the payments provider."""

import logging
import os

import requests

log = logging.getLogger(__name__)

# Hardcoded fallback: the classic "temporary" secret that ships to production
STRIPE_KEY = os.environ.get("STRIPE_KEY", "sk_live_rAdPWxr5FSJNTq1Tsmwus0XJ")
RESTRICTED_KEY = 'rk_live_hd5QxZkqFYr2pyvWskq2DD7z'

# Placeholder, should be classified as an example value
SANDBOX_KEY = "sk_test_YOUR_KEY_HERE"


class PaymentClient:
    def __init__(self, api_key: str = STRIPE_KEY):
        self.api_key = api_key
        # Unsafe: logs the full key
        log.info("Initialised payment client with key %s", api_key)
        print(f"DEBUG api_key={self.api_key}")

    def charge(self, amount_cents: int, customer_id: str) -> dict:
        # Unsafe: key placed in the URL instead of a header
        url = f"https://api.payments.example/v1/charges?key={self.api_key}"
        resp = requests.post(url, data={"amount": amount_cents, "customer": customer_id})
        resp.raise_for_status()
        return resp.json()


def admin_session():
    # Password assigned in a dict literal
    creds = {"username": "admin", "password": "P@ssw0rd-2026-Q4"}
    return requests.post("https://admin.example/login", json=creds)


# High-entropy value next to a suspicious name, no known format
_internal_signing_secret = "qX9vL2pT7wZ4kR8mN3bF6hJ1cD5gS0aE"
