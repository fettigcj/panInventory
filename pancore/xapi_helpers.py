"""
Reusable XAPI troubleshooting helpers.

Purpose
- Provide a simple, importable utility that other scripts can call directly,
  without CLI/argparse, to capture raw XML from XAPI op commands.
- Supports both direct-to-firewall and Panorama-relayed operations by accepting
  the existing pano_obj and fw_obj you already work with across the codebase.

Usage examples

from pancore import xapi_helpers

# 1) Direct to firewall using fw_obj
result = xapi_helpers.run_op_and_capture_raw(
    fw_obj=fw_obj,
    op_cmd_xml='<show><running><resource-monitor><hour><last>24</last></hour></resource-monitor></running></show>',
    is_cmd_xml_literal=True,
    relay_via_panorama=False,
    save_to_file=True
)
print(result['status_detail'], result['saved_file_path'])

# 2) Relay the op through Panorama to the managed firewall
result = xapi_helpers.run_op_and_capture_raw(
    pano_obj=pano_obj,
    fw_obj=fw_obj,
    op_cmd_xml='<show><system><info/></system></show>',
    is_cmd_xml_literal=True,
    relay_via_panorama=True,
    save_to_file=True
)
print(result['anomalies'])

Return value (dict)
- status: SDK response status (e.g., 'success') if available
- status_code: SDK response code if available
- status_detail: Detailed message from the SDK if available
- raw_text: Raw XML (string) that the SDK received (even on parse errors)
- anomalies: List of detected XML 1.0 control characters or unescaped '&'
- saved_file_path: File path if save_to_file was True, otherwise None

Notes
- This uses pan.xapi.PanXapi so it exercises the exact code path that raised
  the ElementTree ParseError in the SDK.
- It does not modify the SDK or sanitize the payload. It only captures and
  analyzes it for your upstream bug report.
"""
from __future__ import annotations

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import re
import os

# We use the SDK's XAPI directly
from pan.xapi import PanXapi, PanXapiError

# Respect the project's logging setup
from pancore import panCore


def _peek_attr(obj: Any, *names: str, default: Any = None) -> Any:
    """Return attribute value from object's __dict__ only (no property access)."""
    if obj is None:
        return default
    obj_dict = getattr(obj, '__dict__', None)
    if not isinstance(obj_dict, dict):
        return default
    for name in names:
        if name in obj_dict:
            return obj_dict.get(name)
    return default


def _get_attr_cautious(obj: Any, name: str, default: Any = None) -> Any:
    """Return attribute via getattr but never raise; use only when needed."""
    if obj is None:
        return default
    try:
        return getattr(obj, name)
    except Exception:
        return default


def _scan_bytes_for_xml_issues(data_bytes: bytes) -> List[Dict[str, Any]]:
    """Scan bytes for XML 1.0 illegal control characters and unescaped ampersands."""
    findings: List[Dict[str, Any]] = []

    for index, value in enumerate(data_bytes):
        if value < 0x20 and value not in (0x09, 0x0A, 0x0D):
            start = max(0, index - 20)
            end = min(len(data_bytes), index + 20)
            context = data_bytes[start:end].decode('utf-8', errors='replace')
            findings.append({
                'type': 'invalid_control_character',
                'offset': index,
                'byte_hex': f"0x{value:02X}",
                'context_preview': context,
            })

    try:
        decoded_text = data_bytes.decode('utf-8')
    except UnicodeDecodeError:
        decoded_text = data_bytes.decode('utf-8', errors='replace')

    amp_pattern = re.compile(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)')
    for match in amp_pattern.finditer(decoded_text):
        start = max(0, match.start() - 20)
        end = min(len(decoded_text), match.end() + 20)
        findings.append({
            'type': 'unescaped_ampersand',
            'char_index': match.start(),
            'context_preview': decoded_text[start:end],
        })

    return findings


def _write_bytes_to_file(data_bytes: bytes, prefix: str, suffix: str = 'xml', base_name: str = 'payload') -> str:
    timestamp_utc = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    safe_base = re.sub(r'[^A-Za-z0-9_.-]', '_', base_name)
    filename = f"{prefix}_{safe_base}_{timestamp_utc}.{suffix}"
    with open(filename, 'wb') as file_handle:
        file_handle.write(data_bytes)
    panCore.logger.info(f"Saved raw payload to: {os.path.abspath(filename)}")
    return filename


def run_op_and_capture_raw(
    *,
    pano_obj: Optional[Any] = None,
    fw_obj: Optional[Any] = None,
    op_cmd_xml: str,
    is_cmd_xml_literal: bool = True,
    relay_via_panorama: bool = False,
    save_to_file: bool = False,
    file_prefix: str = 'xapi_raw_op',
) -> Dict[str, Any]:
    """
    Execute an XAPI op via the pan.xapi SDK and return the raw XML response.

    Parameters
    - pano_obj: Panorama object (required if relay_via_panorama is True)
    - fw_obj: Firewall object (used as direct target or for serial when relaying)
    - op_cmd_xml: The op command to execute. If is_cmd_xml_literal is True,
      this should be the literal XML (e.g., '<show><system><info/></system></show>').
      If False, it will be treated as CLI-style and wrapped by the SDK.
    - is_cmd_xml_literal: Pass True to send literal XML (recommended for op commands).
    - relay_via_panorama: If True, send the op to Panorama with target=<fw serial>.
    - save_to_file: If True, save the raw payload to a timestamped XML file.
    - file_prefix: File prefix for saved payloads.

    Returns
    A dictionary containing status information, the raw text, and analysis results.
    """
    # Important: Avoid touching properties that can trigger network calls (like api_key).
    # Only read from __dict__ where possible, and defer attribute access until we know the branch.

    # Decide how to construct PanXapi
    xapi: Optional[PanXapi] = None

    if relay_via_panorama:
        # Panorama relay path: need panorama hostname/api_key and firewall serial.
        panorama_host = _peek_attr(pano_obj, 'hostname', 'host', default=None) or _get_attr_cautious(pano_obj, 'hostname') or _get_attr_cautious(pano_obj, 'host')
        panorama_api_key = _peek_attr(pano_obj, '_api_key', 'api_key', default=None) or _get_attr_cautious(pano_obj, 'api_key')
        firewall_serial = _peek_attr(fw_obj, 'serial', default=None) or _get_attr_cautious(fw_obj, 'serial')
        target_label = panorama_host
    else:
        # Direct firewall path: need firewall hostname and api_key if available
        firewall_host = _peek_attr(fw_obj, 'hostname', 'host', default=None) or _get_attr_cautious(fw_obj, 'hostname') or _get_attr_cautious(fw_obj, 'host')
        # Try private storage first to avoid property side effects; do NOT fall back to api_key property as it may trigger retrieval
        firewall_api_key = _peek_attr(fw_obj, '_api_key', 'api_key', default=None)
        # Panorama details for potential implicit relay fallback
        panorama_host = _peek_attr(pano_obj, 'hostname', 'host', default=None) or _get_attr_cautious(pano_obj, 'hostname') or _get_attr_cautious(pano_obj, 'host')
        panorama_api_key = _peek_attr(pano_obj, '_api_key', 'api_key', default=None) or _get_attr_cautious(pano_obj, 'api_key')
        firewall_serial = _peek_attr(fw_obj, 'serial', default=None) or _get_attr_cautious(fw_obj, 'serial')
        target_label = firewall_host

    # Now build the PanXapi according to the resolved branch
    try:
        if relay_via_panorama:
            if panorama_host is None or panorama_api_key is None or firewall_serial is None:
                raise ValueError("Relay requires pano_obj with hostname/api_key and fw_obj with serial")
            xapi = PanXapi(hostname=panorama_host, api_key=panorama_api_key, serial=firewall_serial)
        else:
            if firewall_host is not None and firewall_api_key is not None:
                xapi = PanXapi(hostname=firewall_host, api_key=firewall_api_key)
            elif panorama_host is not None and panorama_api_key is not None and firewall_serial is not None:
                panCore.logger.warning("relay_via_panorama was False but only Panorama credentials are available; relaying implicitly.")
                xapi = PanXapi(hostname=panorama_host, api_key=panorama_api_key, serial=firewall_serial)
                relay_via_panorama = True
                target_label = panorama_host
            else:
                raise ValueError("Insufficient credentials: need firewall hostname/api_key or panorama hostname/api_key with firewall serial")
    except Exception as e:
        panCore.logger.error(f"Failed to initialize PanXapi: {e}")
        raise

    try:
        if relay_via_panorama:
            if panorama_host is None or panorama_api_key is None or firewall_serial is None:
                raise ValueError("Relay requires pano_obj with hostname/api_key and fw_obj with serial")
            xapi = PanXapi(hostname=panorama_host, api_key=panorama_api_key, serial=firewall_serial)
        else:
            # Prefer direct firewall; fall back to panorama if only that is provided
            if firewall_host is not None and firewall_api_key is not None:
                xapi = PanXapi(hostname=firewall_host, api_key=firewall_api_key)
            elif panorama_host is not None and panorama_api_key is not None and firewall_serial is not None:
                # If only Panorama creds are present but relay was False, still allow an implicit relay
                panCore.logger.warning("relay_via_panorama was False but only Panorama credentials are available; relaying implicitly.")
                xapi = PanXapi(hostname=panorama_host, api_key=panorama_api_key, serial=firewall_serial)
                relay_via_panorama = True
                target_label = panorama_host
            else:
                raise ValueError("Insufficient credentials: need firewall hostname/api_key or panorama hostname/api_key with firewall serial")
    except Exception as e:
        panCore.logger.error(f"Failed to initialize PanXapi: {e}")
        raise

    # Execute op and capture raw xml_document even if parsing fails
    status = None
    status_code = None
    status_detail = None

    try:
        xapi.op(cmd=op_cmd_xml, cmd_xml=is_cmd_xml_literal)
        status = getattr(xapi, 'status', None)
        status_code = getattr(xapi, 'status_code', None)
        status_detail = getattr(xapi, 'status_detail', None)
    except PanXapiError as e:
        # Even on parse errors, xml_document should be set; capture status_detail
        status_detail = str(e)
        panCore.logger.warning(f"PanXapiError during op(): {e}")
    except Exception as e:
        status_detail = f"Unexpected exception during op(): {e}"
        panCore.logger.exception(status_detail)

    raw_text = getattr(xapi, 'xml_document', None)
    if raw_text is None:
        try:
            maybe_text = xapi.xml_root()  # returns xml_document if element_root is None
            raw_text = maybe_text if isinstance(maybe_text, str) else None
        except Exception:
            raw_text = None

    anomalies: List[Dict[str, Any]] = []
    saved_path: Optional[str] = None

    if raw_text is not None:
        raw_bytes = raw_text.encode('utf-8', errors='replace')
        anomalies = _scan_bytes_for_xml_issues(raw_bytes)
        if save_to_file:
            base_name = target_label or 'unknown-host'
            saved_path = _write_bytes_to_file(raw_bytes, prefix=file_prefix, base_name=base_name)
    else:
        panCore.logger.error("No raw XML available from PanXapi (xml_document is None)")

    return {
        'status': status,
        'status_code': status_code,
        'status_detail': status_detail,
        'raw_text': raw_text,
        'anomalies': anomalies,
        'saved_file_path': saved_path,
        'relayed': relay_via_panorama,
        'target': target_label,
    }
