"""
Photography AI MCP Server
Photo management and analysis tools powered by MEOK AI Labs.
"""

import time
import os
import struct
import hashlib
import math
from datetime import datetime
from collections import defaultdict, Counter
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("photography-ai-mcp")

_call_counts: dict[str, list[float]] = defaultdict(list)
FREE_TIER_LIMIT = 30
WINDOW = 86400


def _check_rate_limit(tool_name: str) -> None:
    now = time.time()
    _call_counts[tool_name] = [t for t in _call_counts[tool_name] if now - t < WINDOW]
    if len(_call_counts[tool_name]) >= FREE_TIER_LIMIT:
        raise ValueError(f"Rate limit exceeded for {tool_name}. Free tier: {FREE_TIER_LIMIT}/day.")
    _call_counts[tool_name].append(now)


# Path traversal protection
BLOCKED_PATH_PATTERNS = ["/etc/", "/var/", "/proc/", "/sys/", "/dev/", ".."]


def _validate_file_path(file_path: str) -> str | None:
    """Validate file path against traversal attacks. Returns error message or None."""
    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern in file_path:
            return f"Access denied: path contains blocked pattern '{pattern}'"
    real = os.path.realpath(file_path)
    if not os.path.isfile(real):
        return f"File not found: {file_path}"
    return None


@mcp.tool()
def analyze_exif(
    file_path: str) -> dict:
    """Analyze EXIF metadata from an image file (JPEG).

    Args:
        file_path: Absolute path to the image file
    """
    _check_rate_limit("analyze_exif")

    path_err = _validate_file_path(file_path)
    if path_err:
        return {"error": path_err}

    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    file_size = os.path.getsize(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    metadata = {
        "file_name": os.path.basename(file_path),
        "file_path": file_path,
        "file_size_bytes": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "extension": ext,
        "modified_time": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
        "created_time": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
    }

    # Try to read basic JPEG EXIF
    if ext in (".jpg", ".jpeg"):
        try:
            with open(file_path, "rb") as f:
                data = f.read(65536)  # Read first 64KB for EXIF

            if data[:2] == b'\xff\xd8':  # JPEG SOI marker
                metadata["format"] = "JPEG"
                # Search for EXIF APP1 marker
                pos = 2
                while pos < len(data) - 4:
                    if data[pos] == 0xFF:
                        marker = data[pos + 1]
                        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                        if marker == 0xE1:  # APP1 (EXIF)
                            metadata["exif_present"] = True
                            exif_data = data[pos + 4:pos + 2 + length]
                            if b"Exif" in exif_data[:10]:
                                metadata["exif_header"] = "Valid EXIF header detected"
                            break
                        pos += 2 + length
                    else:
                        pos += 1
                else:
                    metadata["exif_present"] = False

                # Scan for common EXIF text markers
                text_data = data.decode("latin-1", errors="ignore")
                for tag, patterns in [
                    ("camera_make", ["Canon", "Nikon", "Sony", "Fujifilm", "Olympus", "Panasonic", "Leica", "Apple", "Samsung", "Google"]),
                    ("software", ["Lightroom", "Photoshop", "GIMP", "Capture One", "DxO", "Photos"]),
                ]:
                    for pattern in patterns:
                        if pattern in text_data:
                            metadata[tag] = pattern
                            break
        except Exception as e:
            metadata["read_error"] = str(e)

    elif ext == ".png":
        metadata["format"] = "PNG"
        try:
            with open(file_path, "rb") as f:
                header = f.read(33)
            if header[:8] == b'\x89PNG\r\n\x1a\n':
                if len(header) >= 24:
                    width = struct.unpack(">I", header[16:20])[0]
                    height = struct.unpack(">I", header[20:24])[0]
                    metadata["width"] = width
                    metadata["height"] = height
                    metadata["megapixels"] = round(width * height / 1_000_000, 1)
        except Exception:
            pass

    # Exposure analysis tips based on file properties
    metadata["analysis_tips"] = [
        "For full EXIF extraction, use exiftool or Pillow library",
        "Raw files (.CR2, .NEF, .ARW) contain the most metadata",
        "GPS data may be embedded - check privacy before sharing",
    ]

    return metadata


@mcp.tool()
def map_photo_locations(
    photos: list[dict]) -> dict:
    """Map and cluster photo locations from GPS coordinates.

    Args:
        photos: List of dicts with keys: name, latitude, longitude, date (optional)
    """
    _check_rate_limit("map_photo_locations")

    if not photos:
        return {"error": "No photos provided"}

    # Cluster nearby photos (within ~1km)
    clusters = []
    assigned = set()

    for i, photo in enumerate(photos):
        if i in assigned:
            continue
        lat = float(photo.get("latitude", 0))
        lon = float(photo.get("longitude", 0))
        if lat == 0 and lon == 0:
            continue

        cluster = [photo]
        assigned.add(i)

        for j, other in enumerate(photos):
            if j in assigned:
                continue
            olat = float(other.get("latitude", 0))
            olon = float(other.get("longitude", 0))
            dist = _haversine_km(lat, lon, olat, olon)
            if dist < 1.0:
                cluster.append(other)
                assigned.add(j)

        avg_lat = sum(float(p.get("latitude", 0)) for p in cluster) / len(cluster)
        avg_lon = sum(float(p.get("longitude", 0)) for p in cluster) / len(cluster)
        dates = sorted([p.get("date", "") for p in cluster if p.get("date")])

        clusters.append({
            "center_lat": round(avg_lat, 6),
            "center_lon": round(avg_lon, 6),
            "photo_count": len(cluster),
            "photos": [p.get("name", "unnamed") for p in cluster],
            "date_range": {"earliest": dates[0], "latest": dates[-1]} if dates else None,
        })

    # Calculate total distance traveled
    total_distance = 0
    sorted_photos = sorted(
        [p for p in photos if float(p.get("latitude", 0)) != 0],
        key=lambda p: p.get("date", "")
    )
    for i in range(len(sorted_photos) - 1):
        total_distance += _haversine_km(
            float(sorted_photos[i]["latitude"]), float(sorted_photos[i]["longitude"]),
            float(sorted_photos[i + 1]["latitude"]), float(sorted_photos[i + 1]["longitude"]))

    # Bounding box
    lats = [float(p["latitude"]) for p in photos if float(p.get("latitude", 0)) != 0]
    lons = [float(p["longitude"]) for p in photos if float(p.get("longitude", 0)) != 0]

    return {
        "total_photos": len(photos),
        "geotagged_photos": len(lats),
        "clusters": sorted(clusters, key=lambda c: -c["photo_count"]),
        "total_distance_km": round(total_distance, 1),
        "bounding_box": {
            "north": max(lats) if lats else 0,
            "south": min(lats) if lats else 0,
            "east": max(lons) if lons else 0,
            "west": min(lons) if lons else 0,
        } if lats else None,
    }


def _haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.asin(math.sqrt(a))


@mcp.tool()
def find_duplicates(
    files: list[dict],
    method: str = "hash") -> dict:
    """Find duplicate photos using file hash or metadata comparison.

    Args:
        files: List of dicts with keys: path, size_bytes (optional), date (optional), dimensions (optional, e.g. "4000x3000")
        method: Detection method: hash (file content), metadata (size+date+dimensions), fuzzy (size within 5%)
    """
    _check_rate_limit("find_duplicates")

    duplicates = []
    unique = []

    if method == "hash":
        hash_map = defaultdict(list)
        for f in files:
            path = f.get("path", "")
            if os.path.exists(path):
                try:
                    h = hashlib.md5()
                    with open(path, "rb") as fh:
                        chunk = fh.read(8192)
                        while chunk:
                            h.update(chunk)
                            chunk = fh.read(8192)
                    hash_map[h.hexdigest()].append(path)
                except Exception:
                    unique.append(path)
            else:
                # Use provided data for non-existent files
                key = f"{f.get('size_bytes', '')}{f.get('date', '')}{f.get('dimensions', '')}"
                hash_map[hashlib.md5(key.encode()).hexdigest()].append(path)

        for h, paths in hash_map.items():
            if len(paths) > 1:
                duplicates.append({"hash": h, "files": paths, "count": len(paths)})
            else:
                unique.extend(paths)

    elif method == "metadata":
        meta_map = defaultdict(list)
        for f in files:
            key = f"{f.get('size_bytes', 0)}_{f.get('date', '')}_{f.get('dimensions', '')}"
            meta_map[key].append(f.get("path", ""))

        for key, paths in meta_map.items():
            if len(paths) > 1:
                duplicates.append({"metadata_key": key, "files": paths, "count": len(paths)})
            else:
                unique.extend(paths)

    elif method == "fuzzy":
        sizes = [(i, f.get("size_bytes", 0), f.get("path", "")) for i, f in enumerate(files)]
        sizes.sort(key=lambda x: x[1])
        seen = set()
        for i in range(len(sizes)):
            if i in seen:
                continue
            group = [sizes[i][2]]
            for j in range(i + 1, len(sizes)):
                if j in seen:
                    continue
                if sizes[i][1] > 0 and abs(sizes[j][1] - sizes[i][1]) / sizes[i][1] < 0.05:
                    group.append(sizes[j][2])
                    seen.add(j)
                elif sizes[j][1] > sizes[i][1] * 1.05:
                    break
            if len(group) > 1:
                duplicates.append({"files": group, "count": len(group)})
                seen.add(i)
            else:
                unique.append(sizes[i][2])

    total_dup_files = sum(d["count"] for d in duplicates)
    space_reclaimable = 0
    for d in duplicates:
        for path in d["files"][1:]:
            for f in files:
                if f.get("path") == path:
                    space_reclaimable += f.get("size_bytes", 0)

    return {
        "method": method,
        "total_files": len(files),
        "duplicate_groups": len(duplicates),
        "duplicate_files": total_dup_files,
        "unique_files": len(unique),
        "duplicates": duplicates,
        "space_reclaimable_mb": round(space_reclaimable / (1024 * 1024), 2),
    }


@mcp.tool()
def extract_color_palette(
    colors: list[dict],
    palette_size: int = 6) -> dict:
    """Extract and analyze a color palette from image color data.

    Args:
        colors: List of dicts with keys: r, g, b (0-255), count (optional, pixel count)
        palette_size: Number of dominant colors to return
    """
    _check_rate_limit("extract_color_palette")

    if not colors:
        return {"error": "No color data provided"}

    # Simple color quantization by grouping similar colors
    buckets = defaultdict(lambda: {"r_sum": 0, "g_sum": 0, "b_sum": 0, "count": 0})

    for color in colors:
        r, g, b = int(color["r"]), int(color["g"]), int(color["b"])
        count = int(color.get("count", 1))
        # Quantize to 32-step buckets
        bucket_key = (r // 32, g // 32, b // 32)
        buckets[bucket_key]["r_sum"] += r * count
        buckets[bucket_key]["g_sum"] += g * count
        buckets[bucket_key]["b_sum"] += b * count
        buckets[bucket_key]["count"] += count

    sorted_buckets = sorted(buckets.values(), key=lambda x: -x["count"])
    total_pixels = sum(b["count"] for b in sorted_buckets)

    palette = []
    for bucket in sorted_buckets[:palette_size]:
        n = bucket["count"]
        r = round(bucket["r_sum"] / n)
        g = round(bucket["g_sum"] / n)
        b = round(bucket["b_sum"] / n)
        hex_color = f"#{r:02x}{g:02x}{b:02x}"

        # Classify color
        h, s, l = _rgb_to_hsl(r, g, b)
        if s < 0.1:
            name = "gray" if 0.2 < l < 0.8 else ("black" if l <= 0.2 else "white")
        elif h < 15 or h >= 345:
            name = "red"
        elif h < 45:
            name = "orange"
        elif h < 70:
            name = "yellow"
        elif h < 160:
            name = "green"
        elif h < 200:
            name = "cyan"
        elif h < 260:
            name = "blue"
        elif h < 290:
            name = "purple"
        else:
            name = "pink"

        palette.append({
            "rgb": {"r": r, "g": g, "b": b},
            "hex": hex_color,
            "color_name": name,
            "percentage": round(n / total_pixels * 100, 1),
            "hsl": {"h": round(h), "s": round(s * 100), "l": round(l * 100)},
        })

    # Overall analysis
    avg_brightness = sum(c["hsl"]["l"] for c in palette) / len(palette) if palette else 0
    avg_saturation = sum(c["hsl"]["s"] for c in palette) / len(palette) if palette else 0

    mood = "warm" if any(c["color_name"] in ("red", "orange", "yellow") for c in palette[:3]) else \
           "cool" if any(c["color_name"] in ("blue", "cyan", "purple") for c in palette[:3]) else \
           "neutral"

    return {
        "palette": palette,
        "palette_size": len(palette),
        "total_pixels_analyzed": total_pixels,
        "analysis": {
            "average_brightness": round(avg_brightness, 1),
            "average_saturation": round(avg_saturation, 1),
            "mood": mood,
            "high_key": avg_brightness > 65,
            "low_key": avg_brightness < 35,
        },
        "css_variables": {c["color_name"]: c["hex"] for c in palette},
    }


def _rgb_to_hsl(r, g, b):
    r, g, b = r / 255.0, g / 255.0, b / 255.0
    max_c = max(r, g, b)
    min_c = min(r, g, b)
    l = (max_c + min_c) / 2
    if max_c == min_c:
        h = s = 0
    else:
        d = max_c - min_c
        s = d / (2 - max_c - min_c) if l > 0.5 else d / (max_c + min_c)
        if max_c == r:
            h = (g - b) / d + (6 if g < b else 0)
        elif max_c == g:
            h = (b - r) / d + 2
        else:
            h = (r - g) / d + 4
        h *= 60
    return h, s, l


@mcp.tool()
def edit_metadata(
    file_path: str,
    updates: dict,
    dry_run: bool = True) -> dict:
    """Plan metadata edits for a photo file (generates edit commands).

    Args:
        file_path: Path to the image file
        updates: Dict of metadata fields to update: title, description, copyright, artist, rating (1-5), keywords (list)
        dry_run: If True, only show what would change (default: True for safety)
    """
    _check_rate_limit("edit_metadata")

    valid_fields = {"title", "description", "copyright", "artist", "rating", "keywords", "date_taken", "gps_lat", "gps_lon"}
    invalid = set(updates.keys()) - valid_fields
    if invalid:
        return {"error": f"Invalid metadata fields: {invalid}. Valid fields: {valid_fields}"}

    edits = []
    exiftool_args = []

    for field, value in updates.items():
        if field == "title":
            edits.append({"field": "XMP:Title", "value": value})
            exiftool_args.append(f'-XMP:Title="{value}"')
        elif field == "description":
            edits.append({"field": "EXIF:ImageDescription", "value": value})
            exiftool_args.append(f'-ImageDescription="{value}"')
        elif field == "copyright":
            edits.append({"field": "EXIF:Copyright", "value": value})
            exiftool_args.append(f'-Copyright="{value}"')
        elif field == "artist":
            edits.append({"field": "EXIF:Artist", "value": value})
            exiftool_args.append(f'-Artist="{value}"')
        elif field == "rating":
            rating = max(1, min(5, int(value)))
            edits.append({"field": "XMP:Rating", "value": rating})
            exiftool_args.append(f'-XMP:Rating={rating}')
        elif field == "keywords":
            if isinstance(value, list):
                for kw in value:
                    exiftool_args.append(f'-Keywords="{kw}"')
                edits.append({"field": "IPTC:Keywords", "value": value})
        elif field == "date_taken":
            edits.append({"field": "EXIF:DateTimeOriginal", "value": value})
            exiftool_args.append(f'-DateTimeOriginal="{value}"')

    command = f"exiftool {' '.join(exiftool_args)} \"{file_path}\""

    return {
        "file": file_path,
        "dry_run": dry_run,
        "planned_edits": edits,
        "edit_count": len(edits),
        "exiftool_command": command,
        "note": "Run with dry_run=False and use the exiftool command to apply changes" if dry_run else "Apply the exiftool command to update metadata",
    }


if __name__ == "__main__":
    mcp.run()
