"""
mjpromptsdk.py
Lightweight SDK wrapper for MJ DOOMSDAY LAB Prompt Shield (PromptShield.py)
"""

import json, traceback
from typing import Optional, Dict, Any

try:
    from PromptShield import PromptShield
except Exception:
    try:
        from promptshield import PromptShield
    except Exception as e:
        raise ImportError("Could not import PromptShield. Ensure PromptShield.py is present.") from e

class PromptShieldSDK:
    def __init__(self, sensitivity: str = "medium", config_path: Optional[str] = None, **kwargs):
        try:
            if config_path is not None:
                self._shield = PromptShield(sensitivity=sensitivity, config_path=config_path, **kwargs)
            else:
                try:
                    self._shield = PromptShield(sensitivity=sensitivity, **kwargs)
                except TypeError:
                    self._shield = PromptShield()
            self._ready = True
        except Exception as e:
            self._ready = False
            raise RuntimeError(f"Failed to initialize PromptShield instance: {e}\\n{traceback.format_exc()}")

    def scan(self, text: str, user_id: str = "sdk_user") -> Dict[str, Any]:
        if not self._ready:
            raise RuntimeError("PromptShieldSDK not initialized correctly.")
        try:
            if hasattr(self._shield, "analyze"):
                result = self._shield.analyze(text, user_id=user_id)
            else:
                import asyncio
                result = asyncio.get_event_loop().run_until_complete(self._shield.analyze_async(text, user_id=user_id))
            return self._normalize_result(result)
        except Exception as e:
            return {"error": str(e), "traceback": traceback.format_exc()}

    def _normalize_result(self, result_obj) -> Dict[str, Any]:
        try:
            if isinstance(result_obj, dict):
                return result_obj
            out = {
                "is_malicious": getattr(result_obj, "is_malicious", None),
                "threat_level": getattr(result_obj, "threat_level", None).name if getattr(result_obj, "threat_level", None) is not None else None,
                "score": getattr(result_obj, "score", None),
                "matched_patterns": getattr(result_obj, "matched_patterns", None),
                "reasons": getattr(result_obj, "reasons", None),
                "confidence": getattr(result_obj, "confidence", None),
                "timestamp": getattr(result_obj, "timestamp", None),
                "detection_engine": getattr(result_obj, "detection_engine", None),
            }
            extra = {}
            for k in ("triggered_pattern", "category", "detailed_reasons", "ensemble_votes"):
                v = getattr(result_obj, k, None)
                if v is not None:
                    try:
                        json.dumps(v)
                        extra[k] = v
                    except Exception:
                        extra[k] = str(v)
            out.update(extra)
            return out
        except Exception as e:
            return {"error": "Normalization failed", "traceback": traceback.format_exc(), "obj_repr": str(result_obj)}
