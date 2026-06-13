"""
A3 Security System — OSINT Intelligence Module
Safe public intelligence lookup:
- IP information
- Phone number metadata
- Username public profile checks

This is NOT live tracking.
"""

import requests
import phonenumbers
from phonenumbers import geocoder, carrier, timezone


class OSINTEngine:

    @staticmethod
    def lookup_ip(ip_address):
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=10)
            data = response.json()

            if data.get("status") != "success":
                return {
                    "success": False,
                    "error": data.get("message", "IP lookup failed")
                }

            return {
                "success": True,
                "ip": ip_address,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "map": f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def lookup_phone(phone_number):
        try:
            parsed = phonenumbers.parse(phone_number, None)

            return {
                "success": True,
                "input": phone_number,
                "valid": phonenumbers.is_valid_number(parsed),
                "possible": phonenumbers.is_possible_number(parsed),
                "country": geocoder.description_for_number(parsed, "en"),
                "carrier": carrier.name_for_number(parsed, "en"),
                "timezone": list(timezone.time_zones_for_number(parsed)),
                "international_format": phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                "national_format": phonenumbers.format_number(
                    parsed,
                    phonenumbers.PhoneNumberFormat.NATIONAL
                ),
                "country_code": parsed.country_code,
                "national_number": parsed.national_number
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def lookup_username(username):
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "Instagram": f"https://www.instagram.com/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "Pinterest": f"https://www.pinterest.com/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Twitter/X": f"https://x.com/{username}",
            "Facebook": f"https://www.facebook.com/{username}",
            "YouTube": f"https://www.youtube.com/@{username}",
        }

        results = {}

        headers = {
            "User-Agent": "A3-Security-System/1.0"
        }

        for platform, url in platforms.items():
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=8,
                    allow_redirects=True
                )

                if response.status_code == 200:
                    results[platform] = {
                        "found": True,
                        "url": url
                    }
                else:
                    results[platform] = {
                        "found": False,
                        "url": url
                    }

            except Exception:
                results[platform] = {
                    "found": False,
                    "url": url
                }

        return {
            "success": True,
            "username": username,
            "results": results
        }