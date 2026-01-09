"""
Metadata Analyzer Tool
Extracts and analyzes file metadata including EXIF, timestamps, and file attributes.
"""

import os
import hashlib
import json
import mimetypes
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MetadataAnalyzer:
    """
    Comprehensive metadata extraction and analysis tool.
    Extracts filesystem metadata, file signatures, and document properties.
    """

    def __init__(self):
        self.analyzed_files = []

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Extract comprehensive metadata from a file.

        Args:
            file_path: Path to file to analyze

        Returns:
            Dictionary containing all extracted metadata
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {}

        metadata = {
            'basic_info': self._get_basic_info(file_path),
            'timestamps': self._get_timestamps(file_path),
            'hashes': self._compute_hashes(file_path),
            'file_signature': self._analyze_file_signature(file_path),
            'permissions': self._get_permissions(file_path),
        }

        # Try to extract additional metadata based on file type
        mime_type = mimetypes.guess_type(file_path)[0]

        if mime_type:
            if mime_type.startswith('image/'):
                metadata['exif'] = self._extract_image_metadata(file_path)
            elif mime_type == 'application/pdf':
                metadata['pdf_metadata'] = self._extract_pdf_metadata(file_path)
            elif 'officedocument' in mime_type or 'msword' in mime_type:
                metadata['office_metadata'] = self._extract_office_metadata(file_path)

        self.analyzed_files.append(metadata)
        return metadata

    def _get_basic_info(self, file_path: str) -> Dict[str, Any]:
        """Extract basic file information"""
        stat_info = os.stat(file_path)
        path_obj = Path(file_path)

        return {
            'filename': path_obj.name,
            'full_path': os.path.abspath(file_path),
            'extension': path_obj.suffix,
            'size_bytes': stat_info.st_size,
            'size_human': self._human_readable_size(stat_info.st_size),
            'mime_type': mimetypes.guess_type(file_path)[0],
            'is_hidden': path_obj.name.startswith('.'),
        }

    def _get_timestamps(self, file_path: str) -> Dict[str, str]:
        """Extract MAC (Modified, Accessed, Created) timestamps"""
        stat_info = os.stat(file_path)

        return {
            'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified_unix': int(stat_info.st_mtime),
            'accessed_unix': int(stat_info.st_atime),
            'created_unix': int(stat_info.st_ctime),
        }

    def _compute_hashes(self, file_path: str) -> Dict[str, str]:
        """Compute cryptographic hashes of file content"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)

            return {
                name: hash_obj.hexdigest()
                for name, hash_obj in hashes.items()
            }
        except Exception as e:
            logger.error(f"Error computing hashes: {e}")
            return {}

    def _analyze_file_signature(self, file_path: str) -> Dict[str, Any]:
        """Analyze file signature (magic bytes)"""
        signatures = {
            b'\xFF\xD8\xFF': 'JPEG Image',
            b'\x89\x50\x4E\x47': 'PNG Image',
            b'\x47\x49\x46\x38': 'GIF Image',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\x50\x4B\x03\x04': 'ZIP Archive/Office Document',
            b'\x4D\x5A': 'Windows Executable',
            b'\x7F\x45\x4C\x46': 'Linux ELF Executable',
            b'\x52\x61\x72\x21': 'RAR Archive',
            b'\x1F\x8B': 'GZIP Archive',
            b'\x42\x4D': 'BMP Image',
            b'\x00\x00\x01\x00': 'ICO Image',
            b'\x49\x44\x33': 'MP3 Audio',
            b'\x66\x74\x79\x70': 'MP4 Video',
            b'\x52\x49\x46\x46': 'WAV Audio/AVI Video',
        }

        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

            detected_type = 'Unknown'
            signature_hex = header[:8].hex()

            for sig_bytes, file_type in signatures.items():
                if header.startswith(sig_bytes):
                    detected_type = file_type
                    break

            return {
                'detected_type': detected_type,
                'signature_hex': signature_hex,
                'signature_bytes': list(header[:8]),
            }
        except Exception as e:
            logger.error(f"Error analyzing file signature: {e}")
            return {}

    def _get_permissions(self, file_path: str) -> Dict[str, Any]:
        """Extract file permissions and ownership"""
        stat_info = os.stat(file_path)

        return {
            'mode': oct(stat_info.st_mode),
            'uid': stat_info.st_uid,
            'gid': stat_info.st_gid,
            'is_readable': os.access(file_path, os.R_OK),
            'is_writable': os.access(file_path, os.W_OK),
            'is_executable': os.access(file_path, os.X_OK),
        }

    def _extract_image_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract EXIF and image metadata"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            img = Image.open(file_path)
            exif_data = {}

            # Basic image info
            exif_data['format'] = img.format
            exif_data['mode'] = img.mode
            exif_data['size'] = img.size
            exif_data['width'] = img.width
            exif_data['height'] = img.height

            # Extract EXIF data if available
            exif = img._getexif()
            if exif:
                exif_data['exif'] = {
                    TAGS.get(tag, tag): value
                    for tag, value in exif.items()
                }

            return exif_data

        except ImportError:
            logger.warning("Pillow not installed, skipping image metadata extraction")
            return {'error': 'Pillow library required for image metadata'}
        except Exception as e:
            logger.error(f"Error extracting image metadata: {e}")
            return {'error': str(e)}

    def _extract_pdf_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract PDF metadata"""
        try:
            import PyPDF2

            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)

                metadata = {
                    'page_count': len(pdf.pages),
                    'encrypted': pdf.is_encrypted,
                }

                # Extract document information
                if pdf.metadata:
                    metadata['document_info'] = {
                        key: value
                        for key, value in pdf.metadata.items()
                    }

                return metadata

        except ImportError:
            logger.warning("PyPDF2 not installed, skipping PDF metadata extraction")
            return {'error': 'PyPDF2 library required for PDF metadata'}
        except Exception as e:
            logger.error(f"Error extracting PDF metadata: {e}")
            return {'error': str(e)}

    def _extract_office_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract Microsoft Office document metadata"""
        try:
            from zipfile import ZipFile
            import xml.etree.ElementTree as ET

            metadata = {}

            # Office documents are ZIP files
            with ZipFile(file_path, 'r') as zip_file:
                # Try to read core properties
                try:
                    core_props = zip_file.read('docProps/core.xml')
                    root = ET.fromstring(core_props)

                    # Extract properties
                    namespaces = {
                        'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                        'dc': 'http://purl.org/dc/elements/1.1/',
                        'dcterms': 'http://purl.org/dc/terms/',
                    }

                    metadata['title'] = self._get_xml_text(root, './/dc:title', namespaces)
                    metadata['creator'] = self._get_xml_text(root, './/dc:creator', namespaces)
                    metadata['subject'] = self._get_xml_text(root, './/dc:subject', namespaces)
                    metadata['created'] = self._get_xml_text(root, './/dcterms:created', namespaces)
                    metadata['modified'] = self._get_xml_text(root, './/dcterms:modified', namespaces)

                except KeyError:
                    metadata['error'] = 'Core properties not found'

            return metadata

        except Exception as e:
            logger.error(f"Error extracting Office metadata: {e}")
            return {'error': str(e)}

    def _get_xml_text(self, root, path: str, namespaces: Dict) -> str:
        """Helper to extract text from XML element"""
        element = root.find(path, namespaces)
        return element.text if element is not None else 'N/A'

    def _human_readable_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def analyze_directory(self, directory_path: str, recursive: bool = True) -> List[Dict]:
        """
        Analyze all files in a directory.

        Args:
            directory_path: Path to directory
            recursive: Whether to analyze subdirectories

        Returns:
            List of metadata dictionaries
        """
        results = []
        path_obj = Path(directory_path)

        if recursive:
            files = path_obj.rglob('*')
        else:
            files = path_obj.glob('*')

        for file_path in files:
            if file_path.is_file():
                logger.info(f"Analyzing: {file_path}")
                metadata = self.analyze_file(str(file_path))
                results.append(metadata)

        return results

    def generate_report(self, output_path: str, format: str = 'json') -> None:
        """
        Generate a metadata analysis report.

        Args:
            output_path: Path to save the report
            format: Report format ('json' or 'text')
        """
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(self.analyzed_files, f, indent=2, default=str)
        else:
            with open(output_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("METADATA ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")

                for i, metadata in enumerate(self.analyzed_files, 1):
                    basic = metadata.get('basic_info', {})
                    f.write(f"File #{i}: {basic.get('filename', 'Unknown')}\n")
                    f.write("-" * 80 + "\n")
                    f.write(json.dumps(metadata, indent=2, default=str))
                    f.write("\n\n")

        logger.info(f"Report saved to {output_path}")

    def timeline_analysis(self, output_path: str) -> None:
        """
        Create a forensic timeline from analyzed files.

        Args:
            output_path: Path to save the timeline
        """
        timeline_events = []

        for metadata in self.analyzed_files:
            basic = metadata.get('basic_info', {})
            timestamps = metadata.get('timestamps', {})

            for event_type in ['created', 'modified', 'accessed']:
                if event_type in timestamps:
                    timeline_events.append({
                        'timestamp': timestamps[event_type],
                        'event': event_type.upper(),
                        'file': basic.get('full_path', 'Unknown'),
                        'size': basic.get('size_bytes', 0),
                    })

        # Sort by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])

        # Write timeline
        with open(output_path, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write("FORENSIC TIMELINE\n")
            f.write("=" * 100 + "\n\n")

            for event in timeline_events:
                f.write(f"{event['timestamp']} | {event['event']:<10} | {event['file']}\n")

        logger.info(f"Timeline saved to {output_path}")


def main():
    """Example usage of MetadataAnalyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='Metadata Analyzer Tool')
    parser.add_argument('--file', help='Single file to analyze')
    parser.add_argument('--directory', help='Directory to analyze')
    parser.add_argument('--recursive', action='store_true', help='Recursive analysis')
    parser.add_argument('--output', required=True, help='Output report path')
    parser.add_argument('--format', choices=['json', 'text'], default='json', help='Report format')
    parser.add_argument('--timeline', help='Generate timeline at this path')

    args = parser.parse_args()

    analyzer = MetadataAnalyzer()

    if args.file:
        analyzer.analyze_file(args.file)
    elif args.directory:
        analyzer.analyze_directory(args.directory, args.recursive)
    else:
        parser.error("Either --file or --directory must be specified")

    analyzer.generate_report(args.output, args.format)

    if args.timeline:
        analyzer.timeline_analysis(args.timeline)

    print(f"\n✓ Analysis complete: {len(analyzer.analyzed_files)} files analyzed")


if __name__ == '__main__':
    main()
