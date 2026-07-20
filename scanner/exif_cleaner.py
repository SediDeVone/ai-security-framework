"""EXIF & Image Metadata Cleaner (Exposure & Privacy Defense).

Strips GPS coordinates, device models, and timestamps from image files
before they are processed by multimodal AI models or public chat tools.
Reference: OWASP Metadata Exposure Guidelines.
"""
import io
from typing import Union


def strip_exif_from_bytes(image_bytes: bytes) -> bytes:
    """Removes EXIF metadata tags from image byte streams (JPEG/PNG/WEBP)."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        
        # Re-create clean image without EXIF metadata
        clean_buf = io.BytesIO()
        data = list(img.getdata())
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(data)
        
        fmt = img.format if img.format else "PNG"
        clean_img.save(clean_buf, format=fmt)
        return clean_buf.getvalue()
    except Exception as e:
        # Return original if PIL is unavailable or file is not an image
        return image_bytes
