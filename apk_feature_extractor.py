# Static analysis feature extractor for uploaded APK files, using
# androguard. Produces the exact feature dict expected by
# ApkThreatScoringModel (apk_model.py) and main.py's /analyze-apk endpoint.

import re

try:
    # androguard >= 4.x
    from androguard.core.apk import APK
except ImportError:
    # androguard <= 3.4.x
    from androguard.core.bytecodes.apk import APK


KNOWN_APP_NAMES = {
    "whatsapp", "instagram", "facebook", "gmail", "google play",
    "playstore", "play store", "paytm", "phonepe", "googlepay",
    "google pay", "sbi", "hdfc bank", "icici bank", "amazon",
    "netflix", "youtube", "telegram", "banking",
}

KNOWN_LEGIT_PACKAGE_PREFIXES = (
    "com.whatsapp", "com.instagram", "com.facebook",
    "com.google.android.gm", "com.android.vending",
    "com.google.android.apps", "one.walletsdk", "net.one97.paytm",
    "com.phonepe.app", "com.google.android.apps.nbu.paisa.user",
    "com.sbi.", "com.hdfc", "com.csam.icici",
    "com.amazon.", "com.netflix.", "com.google.android.youtube",
    "org.telegram.messenger",
)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS",
}

SUSPICIOUS_CODE_STRINGS = [
    "DexClassLoader",
    "PathClassLoader",
    "loadDex",
    "dlopen",
    "Runtime.exec",
    "getRuntime().exec",
    "su\x00",
    "/system/bin/su",
    "/system/xbin/su",
    "base64decode",
    "Cipher.getInstance",
    "TelephonyManager.getDeviceId",
    "sendTextMessage",
    "SmsManager",
]


class APKFeatureExtractor:
    """Extracts static-analysis features from an APK file on disk."""

    def extract(self, apk_path: str) -> dict:
        features = self._default_features()

        try:
            apk = APK(apk_path)
        except Exception:
            features["is_unparseable"] = 1
            return features

        # Signing
        try:
            v1 = bool(apk.is_signed_v1())
            v2 = bool(apk.is_signed_v2()) if hasattr(apk, "is_signed_v2") else False
            v3 = bool(apk.is_signed_v3()) if hasattr(apk, "is_signed_v3") else False
            features["is_signed"] = int(v1 or v2 or v3)
            features["has_modern_signature"] = int(v2 or v3)
            features["v1_only_signature"] = int(v1 and not (v2 or v3))
        except Exception:
            pass

        # Manifest / application attributes
        try:
            features["is_debuggable"] = int(
                (apk.get_attribute_value("application", "debuggable") or "").lower()
                == "true"
            )
        except Exception:
            pass

        try:
            features["allows_backup"] = int(
                (apk.get_attribute_value("application", "allowBackup") or "true").lower()
                != "false"
            )
        except Exception:
            features["allows_backup"] = 1

        # SDK version
        try:
            min_sdk = apk.get_min_sdk_version()
            min_sdk = int(min_sdk) if min_sdk is not None else 21
            features["min_sdk_low"] = int(min_sdk < 21)
        except Exception:
            pass

        # Permissions
        try:
            perms = set(apk.get_permissions() or [])
            features["total_permission_count"] = len(perms)
            dangerous = perms & DANGEROUS_PERMISSIONS
            features["dangerous_permission_count"] = len(dangerous)

            features["has_sms_permissions"] = int(
                any("SMS" in p for p in perms)
            )
            features["has_install_packages_permission"] = int(
                "android.permission.REQUEST_INSTALL_PACKAGES" in perms
            )
            features["has_overlay_permission"] = int(
                "android.permission.SYSTEM_ALERT_WINDOW" in perms
            )
            features["has_accessibility_permission"] = int(
                "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
            )
            features["has_device_admin_permission"] = int(
                "android.permission.BIND_DEVICE_ADMIN" in perms
            )
            features["has_contacts_permission"] = int(
                any("CONTACTS" in p for p in perms)
            )

            features["has_trojan_permission_combo"] = int(
                features["has_sms_permissions"]
                and (
                    features["has_overlay_permission"]
                    or features["has_install_packages_permission"]
                    or features["has_accessibility_permission"]
                )
            )
        except Exception:
            pass

        # Identity / package name spoofing
        try:
            package = (apk.get_package() or "").lower()
            app_label = (apk.get_app_name() or "").lower()

            looks_legit = any(
                package.startswith(prefix) for prefix in KNOWN_LEGIT_PACKAGE_PREFIXES
            )
            claims_known_name = any(name in app_label for name in KNOWN_APP_NAMES)

            features["mimics_known_app_name"] = int(claims_known_name and not looks_legit)
        except Exception:
            pass

        # Components
        try:
            activities = apk.get_activities() or []
            services = apk.get_services() or []
            receivers = apk.get_receivers() or []
            providers = apk.get_providers() or []
            features["component_count"] = (
                len(activities) + len(services) + len(receivers) + len(providers)
            )
        except Exception:
            pass

        try:
            features["has_launcher_icon"] = int(
                bool(apk.get_main_activity())
            )
        except Exception:
            pass

        # Dex / native libs / multidex
        try:
            all_files = apk.get_files() or []
            dex_files = [f for f in all_files if f.endswith(".dex")]
            features["multidex"] = int(len(dex_files) > 1)
            features["uses_native_libs"] = int(
                any(f.startswith("lib/") and f.endswith(".so") for f in all_files)
            )
        except Exception:
            pass

        # Suspicious code strings (scan raw dex bytes)
        try:
            hits = 0
            for dex_name in (apk.get_dex_names() if hasattr(apk, "get_dex_names") else ["classes.dex"]):
                try:
                    dex_bytes = apk.get_file(dex_name)
                except Exception:
                    continue
                if not dex_bytes:
                    continue
                try:
                    text = dex_bytes.decode("latin-1", errors="ignore")
                except Exception:
                    continue
                for pattern in SUSPICIOUS_CODE_STRINGS:
                    hits += len(re.findall(re.escape(pattern), text))
            features["suspicious_code_string_hits"] = hits

            features["uses_dynamic_code_loading"] = int(
                any(
                    kw in (locals().get("text") or "")
                    for kw in ("DexClassLoader", "PathClassLoader", "loadDex", "dlopen")
                )
            )
        except Exception:
            pass

        return features

    @staticmethod
    def _default_features() -> dict:
        return {
            "is_unparseable": 0,
            "is_signed": 0,
            "has_modern_signature": 0,
            "v1_only_signature": 0,
            "is_debuggable": 0,
            "allows_backup": 1,
            "min_sdk_low": 0,
            "dangerous_permission_count": 0,
            "total_permission_count": 0,
            "has_sms_permissions": 0,
            "has_install_packages_permission": 0,
            "has_overlay_permission": 0,
            "has_accessibility_permission": 0,
            "has_device_admin_permission": 0,
            "has_contacts_permission": 0,
            "has_trojan_permission_combo": 0,
            "mimics_known_app_name": 0,
            "component_count": 0,
            "multidex": 0,
            "suspicious_code_string_hits": 0,
            "uses_dynamic_code_loading": 0,
            "uses_native_libs": 0,
            "has_launcher_icon": 0,
     }











        
 












