"""
Cross-platform rich clipboard handler.
Supports text, images, HTML, and detects clipboard changes.
"""
import hashlib
import io
import json
import platform
from typing import Dict, Optional, List
from dataclasses import dataclass

# Platform detection
SYSTEM = platform.system()

# Try importing optional dependencies
try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False
    print("[!] pyperclip not installed - text clipboard disabled")

try:
    from PIL import Image, ImageGrab
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("[!] Pillow not installed - image clipboard disabled")

# Windows-specific
HAS_WIN32 = False
if SYSTEM == "Windows":
    try:
        import win32clipboard
        import win32con
        HAS_WIN32 = True
    except ImportError:
        print("[!] pywin32 not installed - Windows rich clipboard disabled")


@dataclass
class ClipboardData:
    """Container for clipboard data in multiple formats"""
    text: Optional[str] = None
    html: Optional[str] = None
    image: Optional[bytes] = None  # PNG bytes
    rtf: Optional[str] = None
    files: Optional[List[str]] = None

    def to_bytes(self) -> bytes:
        """Serialize clipboard data to JSON bytes"""
        data = {
            'text': self.text,
            'html': self.html,
            'image': self.image.hex() if self.image else None,
            'rtf': self.rtf,
            'files': self.files
        }
        return json.dumps(data, ensure_ascii=False).encode('utf-8')

    @staticmethod
    def from_bytes(data: bytes) -> 'ClipboardData':
        """Deserialize clipboard data from JSON bytes"""
        try:
            obj = json.loads(data.decode('utf-8'))
            return ClipboardData(
                text=obj.get('text'),
                html=obj.get('html'),
                image=bytes.fromhex(obj['image']) if obj.get('image') else None,
                rtf=obj.get('rtf'),
                files=obj.get('files')
            )
        except Exception as e:
            print(f"[!] Failed to deserialize clipboard data: {e}")
            return ClipboardData()

    def get_hash(self) -> str:
        """Get SHA256 hash of clipboard content for change detection"""
        return hashlib.sha256(self.to_bytes()).hexdigest()[:16]

    def get_primary_type(self) -> str:
        """Get the primary content type"""
        if self.image:
            return "image"
        elif self.files:
            return "files"
        elif self.html:
            return "html"
        elif self.rtf:
            return "rtf"
        elif self.text:
            return "text"
        else:
            return "empty"

    def get_size(self) -> int:
        """Get total size in bytes"""
        return len(self.to_bytes())

    def get_preview(self, max_len: int = 50) -> str:
        """Get preview string for display"""
        content_type = self.get_primary_type()

        if content_type == "image" and self.image:
            # Try to get image dimensions
            try:
                img = Image.open(io.BytesIO(self.image))
                return f"🖼️ Image {img.width}x{img.height} ({len(self.image):,} bytes)"
            except:
                return f"🖼️ Image ({len(self.image):,} bytes)"

        elif content_type == "files" and self.files:
            file_count = len(self.files)
            return f"📎 {file_count} file(s)"

        elif content_type == "html" and self.html:
            # Strip HTML tags for preview
            import re
            text = re.sub(r'<[^>]+>', '', self.html)
            text = text.strip()[:max_len]
            return f"🌐 {text}..." if len(self.html) > max_len else f"🌐 {text}"

        elif content_type == "rtf" and self.rtf:
            return f"📄 RTF ({len(self.rtf)} chars)"

        elif content_type == "text" and self.text:
            # Clean up text for preview
            preview = self.text.replace('\n', ' ').replace('\r', '')[:max_len]
            if len(self.text) > max_len:
                preview += "..."
            return f"📝 {preview}"

        else:
            return "📋 (empty)"

    def is_empty(self) -> bool:
        """Check if clipboard data is empty"""
        return not any([self.text, self.html, self.image, self.rtf, self.files])


class ClipboardHandler:
    """Cross-platform clipboard handler with rich format support"""

    def __init__(self):
        self.last_hash: Optional[str] = None
        self.capabilities = self._detect_capabilities()

        cap_str = ", ".join(k for k, v in self.capabilities.items() if v)
        print(f"[*] Clipboard capabilities: {cap_str or 'none'}")

    def _detect_capabilities(self) -> Dict[str, bool]:
        """Detect available clipboard capabilities"""
        return {
            'text': HAS_PYPERCLIP,
            'image': HAS_PIL,
            'html': SYSTEM == "Windows" and HAS_WIN32,
            'rtf': SYSTEM == "Windows" and HAS_WIN32,
            'files': SYSTEM == "Windows" and HAS_WIN32,
        }

    def get_clipboard(self) -> ClipboardData:
        """Get current clipboard content in all available formats"""
        data = ClipboardData()

        # Get text (cross-platform)
        if self.capabilities['text']:
            try:
                text = pyperclip.paste()
                if text:
                    data.text = text
            except Exception as e:
                pass  # Silently ignore text errors

        # Get image (cross-platform via PIL)
        if self.capabilities['image']:
            try:
                img = ImageGrab.grabclipboard()
                if img is not None:
                    if isinstance(img, Image.Image):
                        buffer = io.BytesIO()
                        img.save(buffer, format='PNG')
                        data.image = buffer.getvalue()
                    elif isinstance(img, list):
                        # It's a list of files on some platforms
                        data.files = [str(f) for f in img]
            except Exception as e:
                pass  # Silently ignore image errors

        # Windows-specific rich formats
        if HAS_WIN32 and SYSTEM == "Windows":
            try:
                win32clipboard.OpenClipboard()

                # HTML format
                try:
                    cf_html = win32clipboard.RegisterClipboardFormat("HTML Format")
                    if win32clipboard.IsClipboardFormatAvailable(cf_html):
                        html_data = win32clipboard.GetClipboardData(cf_html)
                        if html_data:
                            data.html = html_data.decode('utf-8', errors='ignore')
                except:
                    pass

                # RTF format
                try:
                    cf_rtf = win32clipboard.RegisterClipboardFormat("Rich Text Format")
                    if win32clipboard.IsClipboardFormatAvailable(cf_rtf):
                        rtf_data = win32clipboard.GetClipboardData(cf_rtf)
                        if rtf_data:
                            data.rtf = rtf_data.decode('utf-8', errors='ignore')
                except:
                    pass

                # File drop (if not already got from PIL)
                if not data.files:
                    try:
                        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                            files = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                            if files:
                                data.files = list(files)
                    except:
                        pass

                win32clipboard.CloseClipboard()
            except Exception as e:
                try:
                    win32clipboard.CloseClipboard()
                except:
                    pass

        return data

    def set_clipboard(self, data: ClipboardData) -> bool:
        """Set clipboard content from ClipboardData"""
        success = False

        # Set text (highest priority, cross-platform)
        if data.text and self.capabilities['text']:
            try:
                pyperclip.copy(data.text)
                success = True
            except Exception as e:
                print(f"[!] Error setting text: {e}")

        # Set image on Windows
        if data.image and HAS_WIN32 and SYSTEM == "Windows":
            try:
                # Convert PNG to BMP for Windows clipboard
                img = Image.open(io.BytesIO(data.image))
                output = io.BytesIO()
                img.convert('RGB').save(output, 'BMP')
                bmp_data = output.getvalue()[14:]  # Skip BMP file header

                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32con.CF_DIB, bmp_data)

                # Also set text if available
                if data.text:
                    win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, data.text)

                win32clipboard.CloseClipboard()
                success = True
            except Exception as e:
                print(f"[!] Error setting image: {e}")
                try:
                    win32clipboard.CloseClipboard()
                except:
                    pass

        # Set rich formats on Windows
        if HAS_WIN32 and SYSTEM == "Windows" and (data.html or data.rtf):
            try:
                win32clipboard.OpenClipboard()

                if data.html:
                    cf_html = win32clipboard.RegisterClipboardFormat("HTML Format")
                    win32clipboard.SetClipboardData(cf_html, data.html.encode('utf-8'))

                if data.rtf:
                    cf_rtf = win32clipboard.RegisterClipboardFormat("Rich Text Format")
                    win32clipboard.SetClipboardData(cf_rtf, data.rtf.encode('utf-8'))

                win32clipboard.CloseClipboard()
                success = True
            except Exception as e:
                print(f"[!] Error setting rich formats: {e}")
                try:
                    win32clipboard.CloseClipboard()
                except:
                    pass

        # Update hash after setting
        if success:
            self.last_hash = data.get_hash()

        return success

    def has_changed(self) -> bool:
        """Check if clipboard has changed since last check"""
        try:
            current = self.get_clipboard()
            if current.is_empty():
                return False

            current_hash = current.get_hash()

            if current_hash != self.last_hash:
                self.last_hash = current_hash
                return True
            return False
        except Exception:
            return False

    def get_if_changed(self) -> Optional[ClipboardData]:
        """Get clipboard data only if it has changed"""
        try:
            current = self.get_clipboard()
            if current.is_empty():
                return None

            current_hash = current.get_hash()

            if current_hash != self.last_hash:
                self.last_hash = current_hash
                return current
            return None
        except Exception:
            return None

    def update_hash(self, data: ClipboardData):
        """Update the internal hash without checking for changes"""
        self.last_hash = data.get_hash()
