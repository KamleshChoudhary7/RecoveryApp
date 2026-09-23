import os
import sys
import time
import json
import struct
import sqlite3
import hashlib
import shutil
import zipfile
import threading
import multiprocessing
from multiprocessing import Pool, cpu_count
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import re

# Pillow for EXIF, GPS and Image Repair
try:
    from PIL import Image, ImageFile, ExifTags
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# PyCryptodome for WhatsApp decryption
try:
    from Crypto.Cipher import AES
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False

FILE_SIGNATURES = {
    "Photos_JPEG": {
        "header": b"\xFF\xD8\xFF",
        "footer": b"\xFF\xD9",
        "min_size": 4 * 1024,
        "max_size": 35 * 1024 * 1024,
        "ext": ".jpg",
        "category": "Photos",
        "mime": "image/jpeg"
    },
    "Photos_PNG": {
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "min_size": 2 * 1024,
        "max_size": 30 * 1024 * 1024,
        "ext": ".png",
        "category": "Photos",
        "mime": "image/png"
    },
    "Photos_WEBP": {
        "header": b"RIFF",
        "footer": None,
        "min_size": 2 * 1024,
        "max_size": 25 * 1024 * 1024,
        "ext": ".webp",
        "category": "Photos",
        "mime": "image/webp"
    },
    "Photos_HEIC": {
        "header": b"ftyp",
        "footer": None,
        "min_size": 8 * 1024,
        "max_size": 40 * 1024 * 1024,
        "ext": ".heic",
        "category": "Photos",
        "mime": "image/heic"
    },
    "Videos_MP4": {
        "header": b"ftyp",
        "footer": None,
        "min_size": 30 * 1024,
        "max_size": 300 * 1024 * 1024,
        "ext": ".mp4",
        "category": "Media",
        "mime": "video/mp4"
    },
    "Audio_MP3": {
        "header": b"ID3",
        "footer": None,
        "min_size": 5 * 1024,
        "max_size": 50 * 1024 * 1024,
        "ext": ".mp3",
        "category": "Media",
        "mime": "audio/mpeg"
    },
    "Docs_PDF": {
        "header": b"%PDF-",
        "footer": b"%%EOF",
        "min_size": 1024,
        "max_size": 80 * 1024 * 1024,
        "ext": ".pdf",
        "category": "Documents",
        "mime": "application/pdf"
    },
    "Docs_Office_ZIP": {
        "header": b"PK\x03\x04",
        "footer": b"PK\x05\x06",
        "min_size": 2 * 1024,
        "max_size": 150 * 1024 * 1024,
        "ext": ".zip",
        "category": "Documents",
        "mime": "application/zip"
    },
    "Databases_SQLite": {
        "header": b"SQLite format 3\x00",
        "footer": None,
        "min_size": 512,
        "max_size": 350 * 1024 * 1024,
        "ext": ".db",
        "category": "Databases",
        "mime": "application/x-sqlite3"
    }
}

STATE = {
    "scanning": False,
    "status": "Ready",
    "scanned_mb": 0.0,
    "recovered_count": 0,
    "logs": [],
    "recovered_files": [],
    "seen_hashes": set(),
    "output_dir": "/sdcard/Download/Termux_Recovered_Backups",
    "export_dir": "/sdcard/Download/FORENSIC_EXPORTS"
}

def compute_sha256(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()

def dms_to_degrees(dms_vals, ref):
    try:
        deg = float(dms_vals[0])
        minute = float(dms_vals[1])
        sec = float(dms_vals[2])
        val = deg + (minute / 60.0) + (sec / 3600.0)
        if ref in ["S", "W"]:
            val = -val
        return round(val, 6)
    except Exception:
        return None

def extract_exif_metadata(file_path):
    timestamp = "Date Unknown"
    maps_url = None
    lat_val = None
    lon_val = None

    if PILLOW_AVAILABLE:
        try:
            with Image.open(file_path) as img:
                exif_data = img._getexif()
                if exif_data:
                    for tag_id, val in exif_data.items():
                        tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                        if tag_name in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
                            if isinstance(val, str) and len(val) >= 19:
                                timestamp = val[:19].replace(":", "-", 2)

                        if tag_name == "GPSInfo" and isinstance(val, dict):
                            gps_lat = val.get(2)
                            gps_lat_ref = val.get(1)
                            gps_lon = val.get(4)
                            gps_lon_ref = val.get(3)
                            if gps_lat and gps_lat_ref and gps_lon and gps_lon_ref:
                                lat_val = dms_to_degrees(gps_lat, gps_lat_ref)
                                lon_val = dms_to_degrees(gps_lon, gps_lon_ref)
                                if lat_val is not None and lon_val is not None:
                                    maps_url = f"https://www.google.com/maps?q={lat_val},{lon_val}"
        except Exception:
            pass

    if timestamp == "Date Unknown":
        try:
            with open(file_path, "rb") as f:
                header_chunk = f.read(65536)
            m = re.search(rb"(20[0-2]\d:[0-1]\d:[0-3]\d\s[0-2]\d:[0-5]\d:[0-5]\d)", header_chunk)
            if m:
                timestamp = m.group(1).decode("ascii", errors="ignore").replace(":", "-", 2)
        except Exception:
            pass

    return timestamp, maps_url

def attempt_pillow_repair(file_path):
    if not PILLOW_AVAILABLE:
        return False
    try:
        with Image.open(file_path) as img:
            rgb_conv = img.convert("RGB")
            tmp = file_path + ".fixed.jpg"
            rgb_conv.save(tmp, "JPEG", quality=90)
        os.replace(tmp, file_path)
        return True
    except Exception:
        return False

def parse_sqlite_length(data, start_pos):
    if len(data) < start_pos + 32:
        return None
    try:
        page_size = struct.unpack(">H", data[start_pos + 16 : start_pos + 18])[0]
        if page_size == 1:
            page_size = 65536
        valid_sizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        if page_size not in valid_sizes:
            return None
        page_count = struct.unpack(">I", data[start_pos + 28 : start_pos + 32])[0]
        if page_count > 0:
            total_size = page_size * page_count
            if total_size <= 400 * 1024 * 1024:
                return total_size
    except Exception:
        pass
    return None

def parse_webp_length(data, start_pos):
    if len(data) < start_pos + 12:
        return None
    if data[start_pos : start_pos + 4] == b"RIFF" and data[start_pos + 8 : start_pos + 12] == b"WEBP":
        try:
            riff_size = struct.unpack("<I", data[start_pos + 4 : start_pos + 8])[0]
            total_len = riff_size + 8
            if 1024 <= total_len <= 35 * 1024 * 1024:
                return total_len
        except Exception:
            pass
    return None

def parse_mp4_length(data, start_pos):
    if start_pos < 4 or len(data) < start_pos + 16:
        return None
    major_brand = data[start_pos + 4 : start_pos + 8]
    valid_brands = [b"isom", b"mp41", b"mp42", b"avc1", b"dash", b"MSNV", b"3gp4"]
    if major_brand not in valid_brands:
        return None
    try:
        curr = start_pos - 4
        total_len = 0
        limit = min(len(data), curr + 300 * 1024 * 1024)
        while curr + 8 <= limit:
            box_sz = struct.unpack(">I", data[curr : curr + 4])[0]
            if box_sz == 1:
                # 64-bit atom
                if curr + 16 > limit:
                    break
                box_sz = struct.unpack(">Q", data[curr + 8 : curr + 16])[0]
            if box_sz <= 0 or box_sz > 300 * 1024 * 1024:
                break
            curr += box_sz
            total_len = curr - (start_pos - 4)
            if curr >= limit:
                break
        if total_len >= 32 * 1024:
            return total_len
    except Exception:
        pass
    return None

def parse_heic_length(data, start_pos):
    if start_pos < 4 or len(data) < start_pos + 12:
        return None
    brand = data[start_pos + 4 : start_pos + 8]
    valid_brands = [b"heic", b"mif1", b"msf1", b"heix", b"hevc"]
    if brand in valid_brands:
        try:
            curr = start_pos - 4
            limit = min(len(data), curr + 40 * 1024 * 1024)
            total_len = 0
            while curr + 8 <= limit:
                box_sz = struct.unpack(">I", data[curr : curr + 4])[0]
                if box_sz == 1:
                    if curr + 16 > limit:
                        break
                    box_sz = struct.unpack(">Q", data[curr + 8 : curr + 16])[0]
                if box_sz <= 0 or box_sz > 40 * 1024 * 1024:
                    break
                curr += box_sz
                total_len = curr - (start_pos - 4)
                if curr >= limit:
                    break
            if total_len >= 8 * 1024:
                return total_len
        except Exception:
            pass
    return None

def parse_mp3_length(data, start_pos):
    if len(data) < start_pos + 10:
        return None
    try:
        # ID3v2 tag length encoded as 4 syncsafe bytes (7 bits per byte)
        tag_bytes = data[start_pos + 6 : start_pos + 10]
        tag_sz = ((tag_bytes[0] & 0x7F) << 21) | ((tag_bytes[1] & 0x7F) << 14) | ((tag_bytes[2] & 0x7F) << 7) | (tag_bytes[3] & 0x7F)
        total_header = 10 + tag_sz
        # Carve realistic stream buffer forward (capped at 40MB or next signature boundary)
        stream_len = min(len(data) - start_pos, total_header + 15 * 1024 * 1024)
        if stream_len >= 16 * 1024:
            return stream_len
    except Exception:
        pass
    return None

def verify_jpeg_structure(data_slice):
    if len(data_slice) < 4096 or not data_slice.startswith(b"\xFF\xD8\xFF"):
        return False
    sof_markers = [b"\xFF\xC0", b"\xFF\xC1", b"\xFF\xC2"]
    return any(m in data_slice for m in sof_markers)

def scan_worker_task(args):
    file_path, selected_types, output_base = args
    results = []
    try:
        if not os.path.exists(file_path):
            return results
        with open(file_path, "rb") as f:
            content = f.read()

        c_len = len(content)
        for stype in selected_types:
            sig = FILE_SIGNATURES[stype]
            header = sig["header"]
            footer = sig["footer"]
            ext = sig["ext"]
            cat = sig["category"]
            min_sz = sig["min_size"]
            max_sz = sig["max_size"]

            dest_cat_dir = os.path.join(output_base, cat)
            os.makedirs(dest_cat_dir, exist_ok=True)

            pos = 0
            while True:
                idx = content.find(header, pos)
                if idx == -1:
                    break

                saved = False

                # 1. Databases (SQLite)
                if stype == "Databases_SQLite":
                    db_sz = parse_sqlite_length(content, idx)
                    if db_sz and (idx + db_sz) <= c_len:
                        data_slice = content[idx : idx + db_sz]
                        sha = compute_sha256(data_slice)
                        fname = f"db_{sha[:12]}{ext}"
                        out_file = os.path.join(dest_cat_dir, fname)
                        with open(out_file, "wb") as out_f:
                            out_f.write(data_slice)
                        results.append({
                            "name": fname, "category": cat, "path": out_file,
                            "size": len(data_slice), "date": "N/A", "format": "SQLITE",
                            "maps_url": None, "hash": sha
                        })
                        pos = idx + db_sz
                        saved = True

                # 2. Videos (MP4)
                elif stype == "Videos_MP4":
                    mp4_sz = parse_mp4_length(content, idx)
                    if mp4_sz and (idx - 4 + mp4_sz) <= c_len:
                        start_real = idx - 4
                        data_slice = content[start_real : start_real + mp4_sz]
                        sha = compute_sha256(data_slice)
                        fname = f"rec_vid_{sha[:12]}{ext}"
                        out_file = os.path.join(dest_cat_dir, fname)
                        with open(out_file, "wb") as out_f:
                            out_f.write(data_slice)
                        results.append({
                            "name": fname, "category": cat, "path": out_file,
                            "size": len(data_slice), "date": "N/A", "format": "MP4",
                            "maps_url": None, "hash": sha
                        })
                        pos = start_real + mp4_sz
                        saved = True

                # 3. Audio (MP3)
                elif stype == "Audio_MP3":
                    mp3_sz = parse_mp3_length(content, idx)
                    if mp3_sz and (idx + mp3_sz) <= c_len:
                        data_slice = content[idx : idx + mp3_sz]
                        sha = compute_sha256(data_slice)
                        fname = f"rec_aud_{sha[:12]}{ext}"
                        out_file = os.path.join(dest_cat_dir, fname)
                        with open(out_file, "wb") as out_f:
                            out_f.write(data_slice)
                        results.append({
                            "name": fname, "category": cat, "path": out_file,
                            "size": len(data_slice), "date": "N/A", "format": "MP3",
                            "maps_url": None, "hash": sha
                        })
                        pos = idx + mp3_sz
                        saved = True

                # 4. WebP Image
                elif stype == "Photos_WEBP":
                    webp_sz = parse_webp_length(content, idx)
                    if webp_sz and (idx + webp_sz) <= c_len:
                        data_slice = content[idx : idx + webp_sz]
                        sha = compute_sha256(data_slice)
                        fname = f"rec_webp_{sha[:12]}{ext}"
                        out_file = os.path.join(dest_cat_dir, fname)
                        with open(out_file, "wb") as out_f:
                            out_f.write(data_slice)
                        dt, map_link = extract_exif_metadata(out_file)
                        results.append({
                            "name": fname, "category": cat, "path": out_file,
                            "size": len(data_slice), "date": dt, "format": "WEBP",
                            "maps_url": map_link, "hash": sha
                        })
                        pos = idx + webp_sz
                        saved = True

                # 5. HEIC Image
                elif stype == "Photos_HEIC":
                    heic_sz = parse_heic_length(content, idx)
                    if heic_sz and (idx - 4 + heic_sz) <= c_len:
                        start_real = idx - 4
                        data_slice = content[start_real : start_real + heic_sz]
                        sha = compute_sha256(data_slice)
                        fname = f"rec_heic_{sha[:12]}{ext}"
                        out_file = os.path.join(dest_cat_dir, fname)
                        with open(out_file, "wb") as out_f:
                            out_f.write(data_slice)
                        dt, map_link = extract_exif_metadata(out_file)
                        results.append({
                            "name": fname, "category": cat, "path": out_file,
                            "size": len(data_slice), "date": dt, "format": "HEIC",
                            "maps_url": map_link, "hash": sha
                        })
                        pos = start_real + heic_sz
                        saved = True

                # 6. JPEG Photos with EXIF & GPS
                elif stype == "Photos_JPEG":
                    search_footer_pos = idx + min_sz
                    while search_footer_pos < min(c_len, idx + max_sz):
                        f_idx = content.find(footer, search_footer_pos)
                        if f_idx == -1:
                            if (c_len - idx) >= min_sz:
                                end_idx = min(c_len, idx + 800 * 1024)
                                data_slice = content[idx:end_idx] + b"\xFF\xD9"
                                if verify_jpeg_structure(data_slice):
                                    sha = compute_sha256(data_slice)
                                    fname = f"rec_part_{sha[:12]}{ext}"
                                    out_file = os.path.join(dest_cat_dir, fname)
                                    with open(out_file, "wb") as out_f:
                                        out_f.write(data_slice)
                                    attempt_pillow_repair(out_file)
                                    dt, map_link = extract_exif_metadata(out_file)
                                    results.append({
                                        "name": fname, "category": cat, "path": out_file,
                                        "size": len(data_slice), "date": dt, "format": "JPEG (Fixed)",
                                        "maps_url": map_link, "hash": sha
                                    })
                                    pos = end_idx
                                    saved = True
                            break

                        end_idx = f_idx + len(footer)
                        data_slice = content[idx:end_idx]

                        if verify_jpeg_structure(data_slice):
                            sha = compute_sha256(data_slice)
                            fname = f"rec_{sha[:12]}{ext}"
                            out_file = os.path.join(dest_cat_dir, fname)
                            with open(out_file, "wb") as out_f:
                                out_f.write(data_slice)
                            attempt_pillow_repair(out_file)
                            dt, map_link = extract_exif_metadata(out_file)
                            results.append({
                                "name": fname, "category": cat, "path": out_file,
                                "size": len(data_slice), "date": dt, "format": "JPEG",
                                "maps_url": map_link, "hash": sha
                            })
                            pos = end_idx
                            saved = True
                            break
                        else:
                            search_footer_pos = end_idx + 1

                # 7. Generic Docs (PDF / ZIP)
                elif footer:
                    f_idx = content.find(footer, idx + min_sz)
                    if f_idx != -1:
                        end_idx = f_idx + len(footer)
                        if stype == "Docs_Office_ZIP":
                            end_idx = min(c_len, end_idx + 18)

                        data_len = end_idx - idx
                        if min_sz <= data_len <= max_sz:
                            data_slice = content[idx:end_idx]
                            sha = compute_sha256(data_slice)
                            fname = f"doc_{sha[:12]}{ext}"
                            out_file = os.path.join(dest_cat_dir, fname)
                            with open(out_file, "wb") as out_f:
                                out_f.write(data_slice)
                            results.append({
                                "name": fname, "category": cat, "path": out_file,
                                "size": data_len, "date": "N/A", "format": ext.upper(),
                                "maps_url": None, "hash": sha
                            })
                            pos = end_idx
                            saved = True

                if not saved:
                    pos = idx + 1
    except Exception:
        pass
    return results

class RecoveryManager:
    def __init__(self):
        self.stop_signal = False

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        STATE["logs"].append(entry)
        if len(STATE["logs"]) > 250:
            STATE["logs"].pop(0)

    def start_scan(self, source_type, custom_path, categories, use_mp):
        STATE["scanning"] = True
        STATE["status"] = "Active Forensic Scanning..."
        STATE["recovered_count"] = 0
        STATE["scanned_mb"] = 0.0
        STATE["logs"].clear()
        STATE["recovered_files"].clear()
        STATE["seen_hashes"].clear()
        self.stop_signal = False

        selected_sigs = [k for k, v in FILE_SIGNATURES.items() if v["category"] in categories]

        out_dir = STATE["output_dir"]
        os.makedirs(out_dir, exist_ok=True)
        for cat in ["Photos", "Media", "Documents", "Databases"]:
            os.makedirs(os.path.join(out_dir, cat), exist_ok=True)

        target_paths = self.resolve_targets(source_type, custom_path)
        self.log(f"Targets configured: {len(target_paths)} paths.")

        file_list = []
        for tp in target_paths:
            if os.path.isfile(tp):
                file_list.append(tp)
            elif os.path.isdir(tp):
                for root, _, files in os.walk(tp):
                    for f in files:
                        file_list.append(os.path.join(root, f))

        self.log(f"Found {len(file_list)} storage raw streams & database caches.")

        total_bytes = 0
        if use_mp and len(file_list) > 8:
            cores = max(1, cpu_count() - 1)
            self.log(f"Multi-Core CPU Engine active with {cores} worker processes.")
            tasks = [(fp, selected_sigs, out_dir) for fp in file_list]
            pool = Pool(processes=cores)
            try:
                for res_list in pool.imap_unordered(scan_worker_task, tasks):
                    if self.stop_signal:
                        pool.terminate()
                        break
                    for item in res_list:
                        h = item.get("hash")
                        if h and h in STATE["seen_hashes"]:
                            continue
                        if h:
                            STATE["seen_hashes"].add(h)

                        STATE["recovered_files"].append(item)
                        STATE["recovered_count"] += 1
                        geo_info = " [GPS TAGGED]" if item.get("maps_url") else ""
                        self.log(f"Recovered {item['format']}: {item['name']} ({round(item['size']/1024, 1)} KB){geo_info}")
            except Exception as e:
                self.log(f"Processing error: {str(e)}")
            finally:
                pool.close()
                pool.join()
        else:
            self.log("Running Precision Forensic Scanner.")
            for fp in file_list:
                if self.stop_signal:
                    break
                try:
                    fsize = os.path.getsize(fp)
                    total_bytes += fsize
                    STATE["scanned_mb"] = round(total_bytes / (1024 * 1024), 2)
                    res = scan_worker_task((fp, selected_sigs, out_dir))
                    for item in res:
                        h = item.get("hash")
                        if h and h in STATE["seen_hashes"]:
                            continue
                        if h:
                            STATE["seen_hashes"].add(h)

                        STATE["recovered_files"].append(item)
                        STATE["recovered_count"] += 1
                        geo_info = " [GPS TAGGED]" if item.get("maps_url") else ""
                        self.log(f"Recovered {item['format']}: {item['name']} ({round(item['size']/1024, 1)} KB){geo_info}")
                except Exception:
                    continue

        STATE["scanning"] = False
        STATE["status"] = "Completed"
        self.log(f"Scan finished. Unique forensic items extracted: {STATE['recovered_count']}")

    def resolve_targets(self, source_type, custom_path):
        paths = []
        if source_type == "THUMBNAILS":
            candidate_dirs = [
                "/sdcard/DCIM/.thumbnails",
                "/sdcard/Pictures/.thumbnails",
                "/sdcard/.trash",
                "/sdcard/Android/media/com.whatsapp/WhatsApp/Media/.trash",
                "/sdcard/Android/data/com.miui.gallery/cache",
                "/sdcard/Android/data/com.sec.android.gallery3d/cache",
                "/sdcard/Android/data/com.google.android.apps.photos/cache"
            ]
            for cd in candidate_dirs:
                if os.path.exists(cd):
                    paths.append(cd)
        elif source_type == "OTG":
            base_storage = "/storage"
            if os.path.exists(base_storage):
                for entry in os.listdir(base_storage):
                    if entry not in ["emulated", "self"]:
                        otg_dir = os.path.join(base_storage, entry)
                        if os.path.isdir(otg_dir):
                            paths.append(otg_dir)
        elif source_type == "STORAGE_ROOT":
            paths.append("/sdcard/DCIM")
            paths.append("/sdcard/Pictures")
            paths.append("/sdcard/Movies")
            paths.append("/sdcard/Music")
            paths.append("/sdcard/Download")
            paths.append("/sdcard/Android/media/com.whatsapp/WhatsApp/Media")
        elif source_type == "CUSTOM" and custom_path:
            if os.path.exists(custom_path):
                paths.append(custom_path)

        if not paths:
            paths.append("/sdcard/Download")
        return paths

RECOVERY_ENGINE = RecoveryManager()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mobile Forensic Studio Pro</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0b0d13; color: #dbe2ef; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 10px; }
  .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 8px; border-bottom: 1px solid #1a1e29; margin-bottom: 10px; }
  .header h2 { font-size: 1.05rem; color: #61afef; font-weight: 700; letter-spacing: 0.5px; }
  .badge { background: #161922; color: #98c379; padding: 3px 6px; border-radius: 4px; font-size: 0.72rem; font-weight: bold; }
  .card { background: #131722; border-radius: 6px; padding: 10px; margin-bottom: 10px; }
  .card h3 { font-size: 0.82rem; color: #7f8c98; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
  .row { display: flex; gap: 6px; margin-bottom: 6px; flex-wrap: wrap; }
  label { display: flex; align-items: center; gap: 5px; font-size: 0.8rem; cursor: pointer; }
  select, input[type="text"] { width: 100%; background: #07080c; border: 1px solid #232838; color: #fff; padding: 7px; border-radius: 4px; font-size: 0.82rem; }
  .btn { background: #007acc; color: white; border: none; padding: 8px 12px; border-radius: 4px; font-size: 0.85rem; font-weight: bold; cursor: pointer; width: 100%; }
  .btn:active { background: #005999; }
  .btn-stop { background: #d13b3b; margin-top: 5px; }
  .btn-action { background: #232838; color: #dbe2ef; padding: 6px 10px; font-size: 0.75rem; border-radius: 4px; border: 1px solid #333a4f; cursor: pointer; }
  .btn-danger { background: #7c2222; color: #fff; border-color: #992b2b; }
  .btn-success { background: #1e5c33; color: #fff; border-color: #297a44; }
  .stats-bar { display: flex; justify-content: space-between; font-size: 0.75rem; color: #61afef; padding: 5px 0; font-weight: 600; }
  .console { background: #07080c; border-radius: 4px; height: 110px; overflow-y: scroll; padding: 6px; font-family: monospace; font-size: 0.72rem; color: #98c379; white-space: pre-wrap; }

  /* Media Grid */
  .media-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; max-height: 480px; overflow-y: auto; padding: 2px; }
  .media-card { background: #07080c; border: 1px solid #232838; border-radius: 5px; overflow: hidden; display: flex; flex-direction: column; position: relative; }
  .media-card.selected { border: 2px solid #007acc; background: #0d1a29; }
  .media-card img, .media-card video { width: 100%; height: 115px; object-fit: cover; background: #131722; display: block; }
  .audio-placeholder { height: 115px; display: flex; align-items: center; justify-content: center; background: #161a26; font-size: 1.8rem; }
  
  .card-chk { position: absolute; top: 4px; left: 4px; z-index: 10; width: 16px; height: 16px; cursor: pointer; }
  .media-meta { padding: 5px; font-size: 0.65rem; color: #abb2bf; display: flex; flex-direction: column; gap: 2px; }
  .meta-top { display: flex; justify-content: space-between; align-items: center; }
  .tag { background: #161922; color: #61afef; padding: 1px 3px; border-radius: 3px; font-size: 0.58rem; font-weight: bold; }
  .meta-date { color: #e5c07b; font-family: monospace; font-size: 0.62rem; }
  .map-link { color: #98c379; text-decoration: none; font-weight: bold; font-size: 0.65rem; }

  .bulk-bar { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid #1a1e29; }

  .nav-tabs { display: flex; gap: 3px; margin-bottom: 10px; }
  .nav-tab { flex: 1; text-align: center; padding: 7px; background: #131722; color: #687385; border-radius: 4px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
  .nav-tab.active { background: #007acc; color: white; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 0.72rem; }
  th, td { border: 1px solid #232838; padding: 5px; text-align: left; }
  th { background: #161922; color: #61afef; }
</style>
</head>
<body>

<div class="header">
  <h2>INVESTIGATION RECOVERY ENGINE</h2>
  <span class="badge">EVIDENCE PRO</span>
</div>

<div class="nav-tabs">
  <div class="nav-tab active" onclick="switchTab('carver')">RECOVERY</div>
  <div class="nav-tab" onclick="switchTab('gallery')">PHOTOS STREAM</div>
  <div class="nav-tab" onclick="switchTab('media')">AUDIO/VIDEO</div>
  <div class="nav-tab" onclick="switchTab('sqlite')">SQLITE VIEWER</div>
  <div class="nav-tab" onclick="switchTab('whatsapp')">WHATSAPP</div>
</div>

<div id="tab-carver" class="tab-content active">
  <div class="card">
    <h3>1. Target Source Location</h3>
    <select id="source_type" onchange="toggleCustomPath()">
      <option value="STORAGE_ROOT">Full Internal Shared Memory (DCIM, Pictures, Media, Downloads)</option>
      <option value="THUMBNAILS">Trashes & Gallery Hidden Cache (.thumbnails)</option>
      <option value="OTG">Attached OTG Pendrive / SD Card</option>
      <option value="CUSTOM">Specific Folder / Raw Partition</option>
    </select>
    <div id="custom_path_div" style="display:none; margin-top: 6px;">
      <input type="text" id="custom_path" placeholder="/sdcard/DCIM/Camera">
    </div>
  </div>

  <div class="card">
    <h3>2. Categories & Multi-Core Acceleration</h3>
    <div class="row">
      <label><input type="checkbox" id="cat_photos" checked> Photos (JPG/PNG/WEBP/HEIC)</label>
      <label><input type="checkbox" id="cat_media" checked> Video / Audio (MP4/MP3)</label>
      <label><input type="checkbox" id="cat_docs" checked> Docs (PDF/ZIP)</label>
      <label><input type="checkbox" id="cat_db" checked> Databases (SQLite)</label>
    </div>
    <div style="margin-top: 6px;">
      <label><input type="checkbox" id="use_mp" checked> Multi-Core Engine (Fast Hardware Parallel Scan)</label>
    </div>
  </div>

  <div class="card">
    <button class="btn" onclick="startScan()">START INVESTIGATION RECOVERY</button>
    <button class="btn btn-stop" onclick="stopScan()">STOP ENGINE</button>
    <div class="stats-bar">
      <span id="stat_status">Status: Ready</span>
      <span id="stat_recovered">Recovered: 0</span>
    </div>
    <div class="console" id="log_box">System ready. Click START to scan suspect device.</div>
  </div>
</div>

<div id="tab-gallery" class="tab-content">
  <div class="card">
    <div class="bulk-bar">
      <button class="btn-action" onclick="selectAll('Photos', true)">Select All</button>
      <button class="btn-action" onclick="selectAll('Photos', false)">Deselect</button>
      <button class="btn-action btn-success" onclick="bulkExport('Photos')">Save Selected to Phone</button>
      <button class="btn-action btn-danger" onclick="bulkDelete('Photos')">Delete Selected</button>
      <button class="btn-action" style="margin-left:auto;" onclick="refreshGallery()">Refresh</button>
    </div>
    <div class="media-grid" id="gallery_grid">
      <p style="color:#5c6370; font-size:0.75rem;">No photos discovered yet.</p>
    </div>
  </div>
</div>

<div id="tab-media" class="tab-content">
  <div class="card">
    <div class="bulk-bar">
      <button class="btn-action" onclick="selectAll('Media', true)">Select All</button>
      <button class="btn-action" onclick="selectAll('Media', false)">Deselect</button>
      <button class="btn-action btn-success" onclick="bulkExport('Media')">Save Selected to Phone</button>
      <button class="btn-action btn-danger" onclick="bulkDelete('Media')">Delete Selected</button>
      <button class="btn-action" style="margin-left:auto;" onclick="refreshMedia()">Refresh</button>
    </div>
    <div class="media-grid" id="media_grid">
      <p style="color:#5c6370; font-size:0.75rem;">No audio or video recovered yet.</p>
    </div>
  </div>
</div>

<div id="tab-sqlite" class="tab-content">
  <div class="card">
    <h3>SQLite Database Inspector</h3>
    <input type="text" id="sqlite_path" placeholder="/sdcard/Download/Termux_Recovered_Backups/Databases/file.db">
    <button class="btn" style="margin-top: 6px;" onclick="loadDbTables()">LOAD TABLES</button>
    <div style="margin-top: 6px;">
      <select id="db_tables" onchange="loadTableData()"></select>
    </div>
  </div>
  <div class="card" style="overflow-x: auto; max-height: 250px;">
    <table id="db_table_view"></table>
  </div>
</div>

<div id="tab-whatsapp" class="tab-content">
  <div class="card">
    <h3>WhatsApp Crypt Decryptor</h3>
    <input type="text" id="wa_crypt" placeholder="Path to msgstore.db.crypt14" style="margin-bottom:6px;">
    <input type="text" id="wa_key" placeholder="Path to key file" style="margin-bottom:6px;">
    <button class="btn" onclick="decryptWhatsApp()">DECRYPT TO SQLITE</button>
    <div id="wa_status" style="margin-top:8px; font-size:0.75rem; color:#98c379;"></div>
  </div>
</div>

<script>
function switchTab(name) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  event.target.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
  if(name === 'gallery') refreshGallery();
  if(name === 'media') refreshMedia();
}

function toggleCustomPath() {
  var s = document.getElementById('source_type').value;
  document.getElementById('custom_path_div').style.display = (s === 'CUSTOM') ? 'block' : 'none';
}

function startScan() {
  var payload = {
    source_type: document.getElementById('source_type').value,
    custom_path: document.getElementById('custom_path').value,
    photos: document.getElementById('cat_photos').checked,
    media: document.getElementById('cat_media').checked,
    docs: document.getElementById('cat_docs').checked,
    db: document.getElementById('cat_db').checked,
    mp: document.getElementById('use_mp').checked
  };
  fetch('/api/start', { method: 'POST', body: JSON.stringify(payload) });
}

function stopScan() {
  fetch('/api/stop', { method: 'POST' });
}

function updatePoll() {
  fetch('/api/status').then(r => r.json()).then(d => {
    document.getElementById('stat_status').innerText = 'Status: ' + d.status;
    document.getElementById('stat_recovered').innerText = 'Recovered: ' + d.recovered_count;
    var logBox = document.getElementById('log_box');
    logBox.innerText = d.logs.join('\\n');
    logBox.scrollTop = logBox.scrollHeight;
  });
}
setInterval(updatePoll, 1000);

function renderMediaCard(f, isVideoAudio) {
  var card = document.createElement('div');
  card.className = 'media-card';
  card.dataset.path = f.path;

  var chk = document.createElement('input');
  chk.type = 'checkbox';
  chk.className = 'card-chk';
  chk.dataset.category = f.category;
  chk.onchange = function() { card.classList.toggle('selected', chk.checked); };
  card.appendChild(chk);

  var src = '/view_file?path=' + encodeURIComponent(f.path);
  if (f.format === 'MP4') {
    var v = document.createElement('video');
    v.src = src;
    v.controls = true;
    card.appendChild(v);
  } else if (f.format === 'MP3') {
    var ph = document.createElement('div');
    ph.className = 'audio-placeholder';
    ph.innerHTML = '&#127911;';
    card.appendChild(ph);
    var aud = document.createElement('audio');
    aud.src = src;
    aud.controls = true;
    aud.style.width = '100%';
    card.appendChild(aud);
  } else {
    var img = document.createElement('img');
    img.src = src;
    img.onclick = function() { window.open(src, '_blank'); };
    card.appendChild(img);
  }

  var meta = document.createElement('div');
  meta.className = 'media-meta';
  var kb = Math.round(f.size / 1024) + ' KB';
  
  var mapHtml = f.maps_url ? '<a class="map-link" href="' + f.maps_url + '" target="_blank">&#127757; View GPS Map</a>' : '';

  meta.innerHTML = 
    '<div class="meta-top"><span class="tag">' + f.format + '</span><span>' + kb + '</span></div>' +
    '<div class="meta-date">&#128338; ' + (f.date || 'N/A') + '</div>' +
    mapHtml;

  card.appendChild(meta);
  return card;
}

function refreshGallery() {
  fetch('/api/items?category=Photos').then(r => r.json()).then(files => {
    var grid = document.getElementById('gallery_grid');
    if(!files || files.length === 0) {
      grid.innerHTML = '<p style="color:#5c6370; font-size:0.75rem;">No photos discovered yet.</p>';
      return;
    }
    grid.innerHTML = '';
    files.forEach(f => grid.appendChild(renderMediaCard(f, false)));
  });
}

function refreshMedia() {
  fetch('/api/items?category=Media').then(r => r.json()).then(files => {
    var grid = document.getElementById('media_grid');
    if(!files || files.length === 0) {
      grid.innerHTML = '<p style="color:#5c6370; font-size:0.75rem;">No audio or video recovered yet.</p>';
      return;
    }
    grid.innerHTML = '';
    files.forEach(f => grid.appendChild(renderMediaCard(f, true)));
  });
}

function selectAll(category, checked) {
  document.querySelectorAll('.card-chk[data-category="' + category + '"]').forEach(c => {
    c.checked = checked;
    c.parentElement.classList.toggle('selected', checked);
  });
}

function getSelectedPaths(category) {
  var paths = [];
  document.querySelectorAll('.card-chk[data-category="' + category + '"]:checked').forEach(c => {
    paths.push(c.parentElement.dataset.path);
  });
  return paths;
}

function bulkDelete(category) {
  var paths = getSelectedPaths(category);
  if(paths.length === 0) { alert('No items selected.'); return; }
  if(!confirm('Permanently delete ' + paths.length + ' item(s) from recovered cache?')) return;
  fetch('/api/bulk_delete', { method: 'POST', body: JSON.stringify({ paths: paths }) })
    .then(r => r.json()).then(d => {
      alert(d.message);
      if(category === 'Photos') refreshGallery();
      if(category === 'Media') refreshMedia();
    });
}

function bulkExport(category) {
  var paths = getSelectedPaths(category);
  if(paths.length === 0) { alert('No items selected.'); return; }
  fetch('/api/bulk_export', { method: 'POST', body: JSON.stringify({ paths: paths }) })
    .then(r => r.json()).then(d => {
      alert(d.message + '\\nSaved to: ' + d.export_path);
    });
}

function loadDbTables() {
  var p = document.getElementById('sqlite_path').value;
  fetch('/api/sqlite/tables?path=' + encodeURIComponent(p)).then(r => r.json()).then(d => {
    var sel = document.getElementById('db_tables');
    sel.innerHTML = '';
    if(d.tables) {
      d.tables.forEach(t => {
        var opt = document.createElement('option');
        opt.value = t; opt.innerText = t;
        sel.appendChild(opt);
      });
      loadTableData();
    }
  });
}

function loadTableData() {
  var p = document.getElementById('sqlite_path').value;
  var t = document.getElementById('db_tables').value;
  fetch('/api/sqlite/rows?path=' + encodeURIComponent(p) + '&table=' + encodeURIComponent(t))
    .then(r => r.json()).then(d => {
      var tbl = document.getElementById('db_table_view');
      tbl.innerHTML = '';
      if(d.columns && d.rows) {
        var trH = document.createElement('tr');
        d.columns.forEach(c => { var th = document.createElement('th'); th.innerText = c; trH.appendChild(th); });
        tbl.appendChild(trH);
        d.rows.forEach(r => {
          var tr = document.createElement('tr');
          r.forEach(v => { var td = document.createElement('td'); td.innerText = (v !== null) ? String(v).slice(0, 50) : 'NULL'; tr.appendChild(td); });
          tbl.appendChild(tr);
        });
      }
    });
}

function decryptWhatsApp() {
  var c = document.getElementById('wa_crypt').value;
  var k = document.getElementById('wa_key').value;
  document.getElementById('wa_status').innerText = 'Processing decryption...';
  fetch('/api/whatsapp/decrypt', {
    method: 'POST',
    body: JSON.stringify({ crypt: c, key: k })
  }).then(r => r.json()).then(d => {
    document.getElementById('wa_status').innerText = d.message;
  });
}
</script>
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

        elif url.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(STATE, default=list).encode("utf-8"))

        elif url.path == "/api/items":
            qs = urllib.parse.parse_qs(url.query)
            cat = qs.get("category", ["Photos"])[0]
            items = [f for f in STATE["recovered_files"] if f.get("category") == cat]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(items).encode("utf-8"))

        elif url.path == "/view_file":
            qs = urllib.parse.parse_qs(url.query)
            fpath = qs.get("path", [""])[0]
            if os.path.exists(fpath):
                try:
                    with open(fpath, "rb") as rf:
                        file_bytes = rf.read()
                    self.send_response(200)
                    if fpath.endswith(".jpg"):
                        self.send_header("Content-Type", "image/jpeg")
                    elif fpath.endswith(".png"):
                        self.send_header("Content-Type", "image/png")
                    elif fpath.endswith(".webp"):
                        self.send_header("Content-Type", "image/webp")
                    elif fpath.endswith(".heic"):
                        self.send_header("Content-Type", "image/heic")
                    elif fpath.endswith(".mp4"):
                        self.send_header("Content-Type", "video/mp4")
                    elif fpath.endswith(".mp3"):
                        self.send_header("Content-Type", "audio/mpeg")
                    else:
                        self.send_header("Content-Type", "application/octet-stream")

                    self.send_header("Content-Length", str(len(file_bytes)))
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    self.wfile.write(file_bytes)
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        elif url.path == "/api/sqlite/tables":
            qs = urllib.parse.parse_qs(url.query)
            db_path = qs.get("path", [""])[0]
            tables = []
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
                    tables = [r[0] for r in cur.fetchall()]
                    conn.close()
                except Exception:
                    pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"tables": tables}).encode("utf-8"))

        elif url.path == "/api/sqlite/rows":
            qs = urllib.parse.parse_qs(url.query)
            db_path = qs.get("path", [""])[0]
            tbl_name = qs.get("table", [""])[0]
            cols, rows = [], []
            if os.path.exists(db_path) and tbl_name:
                try:
                    conn = sqlite3.connect(db_path)
                    cur = conn.cursor()
                    cur.execute(f"PRAGMA table_info({tbl_name});")
                    cols = [c[1] for c in cur.fetchall()]
                    cur.execute(f"SELECT * FROM {tbl_name} LIMIT 60;")
                    rows = cur.fetchall()
                    conn.close()
                except Exception:
                    pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"columns": cols, "rows": rows}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)

        if url.path == "/api/start":
            data = json.loads(post_body.decode("utf-8"))
            cats = []
            if data.get("photos"): cats.append("Photos")
            if data.get("media"): cats.append("Media")
            if data.get("docs"): cats.append("Documents")
            if data.get("db"): cats.append("Databases")

            t = threading.Thread(
                target=RECOVERY_ENGINE.start_scan,
                args=(data.get("source_type"), data.get("custom_path"), cats, data.get("mp", True)),
                daemon=True
            )
            t.start()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"started"}')

        elif url.path == "/api/stop":
            RECOVERY_ENGINE.stop_signal = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"stopping"}')

        elif url.path == "/api/bulk_delete":
            data = json.loads(post_body.decode("utf-8"))
            paths = data.get("paths", [])
            del_count = 0
            for p in paths:
                try:
                    if os.path.exists(p):
                        os.remove(p)
                        del_count += 1
                except Exception:
                    pass
            STATE["recovered_files"] = [f for f in STATE["recovered_files"] if f.get("path") not in paths]
            STATE["recovered_count"] = len(STATE["recovered_files"])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": f"Successfully deleted {del_count} file(s)."}).encode("utf-8"))

        elif url.path == "/api/bulk_export":
            data = json.loads(post_body.decode("utf-8"))
            paths = data.get("paths", [])
            export_target = STATE["export_dir"]
            os.makedirs(export_target, exist_ok=True)
            saved_count = 0
            for p in paths:
                try:
                    if os.path.exists(p):
                        dest = os.path.join(export_target, os.path.basename(p))
                        shutil.copy2(p, dest)
                        saved_count += 1
                except Exception:
                    pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            res = {"message": f"Exported {saved_count} file(s) directly to Mobile Storage.", "export_path": export_target}
            self.wfile.write(json.dumps(res).encode("utf-8"))

        elif url.path == "/api/whatsapp/decrypt":
            data = json.loads(post_body.decode("utf-8"))
            crypt_p = data.get("crypt")
            key_p = data.get("key")
            msg = ""
            if not PYCRYPTODOME_AVAILABLE:
                msg = "pycryptodome library missing."
            elif not os.path.exists(crypt_p) or not os.path.exists(key_p):
                msg = "Invalid file path."
            else:
                try:
                    with open(key_p, "rb") as kf:
                        k_data = kf.read()
                    aes_key = k_data if len(k_data) < 158 else k_data[126:158]
                    with open(crypt_p, "rb") as cf:
                        c_data = cf.read()
                    iv = c_data[67:83]
                    payload = c_data[190:-16]
                    tag = c_data[-16:]
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
                    decrypted = cipher.decrypt_and_verify(payload, tag)
                    out_db = crypt_p + "_decrypted.db"
                    with open(out_db, "wb") as out_f:
                        out_f.write(decrypted)
                    msg = f"Decrypted: {out_db}"
                except Exception as ex:
                    msg = f"Decryption error: {str(ex)}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": msg}).encode("utf-8"))

def auto_open_browser():
    time.sleep(1.0)
    res = os.system("termux-open-url http://127.0.0.1:8080")
    if res != 0:
        os.system("am start -a android.intent.action.VIEW -d http://127.0.0.1:8080 > /dev/null 2>&1")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    server_address = ("127.0.0.1", 8080)
    httpd = HTTPServer(server_address, RequestHandler)
    print("--------------------------------------------------")
    print(" Forensic Investigation Recovery Engine Online ")
    print(" Dashboard URL: http://127.0.0.1:8080")
    print("--------------------------------------------------")

    browser_thread = threading.Thread(target=auto_open_browser, daemon=True)
    browser_thread.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
        sys.exit(0)
