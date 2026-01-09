"""
File Recovery Tool
Recovers deleted files from disk images and storage devices using file signature detection.
"""

import os
import struct
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FileSignature:
    """File signature database for file carving"""

    SIGNATURES = {
        # Image formats
        'jpg': {'header': b'\xFF\xD8\xFF', 'footer': b'\xFF\xD9', 'extension': '.jpg'},
        'png': {'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82', 'extension': '.png'},
        'gif': {'header': b'\x47\x49\x46\x38', 'footer': b'\x00\x3B', 'extension': '.gif'},
        'bmp': {'header': b'\x42\x4D', 'footer': None, 'extension': '.bmp'},

        # Document formats
        'pdf': {'header': b'\x25\x50\x44\x46', 'footer': b'\x25\x25\x45\x4F\x46', 'extension': '.pdf'},
        'docx': {'header': b'\x50\x4B\x03\x04', 'footer': None, 'extension': '.docx'},
        'xlsx': {'header': b'\x50\x4B\x03\x04', 'footer': None, 'extension': '.xlsx'},
        'zip': {'header': b'\x50\x4B\x03\x04', 'footer': None, 'extension': '.zip'},

        # Executable formats
        'exe': {'header': b'\x4D\x5A', 'footer': None, 'extension': '.exe'},
        'dll': {'header': b'\x4D\x5A', 'footer': None, 'extension': '.dll'},

        # Media formats
        'mp3': {'header': b'\xFF\xFB', 'footer': None, 'extension': '.mp3'},
        'mp4': {'header': b'\x00\x00\x00\x18\x66\x74\x79\x70', 'footer': None, 'extension': '.mp4'},
        'avi': {'header': b'\x52\x49\x46\x46', 'footer': None, 'extension': '.avi'},

        # Database formats
        'sqlite': {'header': b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33', 'footer': None, 'extension': '.db'},

        # Text formats
        'txt': {'header': None, 'footer': None, 'extension': '.txt'},
    }


class FileRecoveryTool:
    """
    Advanced file recovery tool using file carving techniques.
    Supports recovery of deleted files from disk images and raw storage.
    """

    def __init__(self, chunk_size: int = 512):
        self.chunk_size = chunk_size
        self.recovered_files = []

    def scan_disk_image(self, image_path: str, output_dir: str) -> List[Dict]:
        """
        Scan a disk image for recoverable files using file signatures.

        Args:
            image_path: Path to disk image file
            output_dir: Directory to save recovered files

        Returns:
            List of recovered file information
        """
        logger.info(f"Starting file recovery scan on {image_path}")

        if not os.path.exists(image_path):
            logger.error(f"Disk image not found: {image_path}")
            return []

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        recovered = []

        with open(image_path, 'rb') as disk:
            offset = 0
            buffer = disk.read(self.chunk_size * 1024)  # Read 512KB chunks

            while buffer:
                # Search for file signatures in buffer
                for file_type, sig_info in FileSignature.SIGNATURES.items():
                    if sig_info['header']:
                        pos = buffer.find(sig_info['header'])

                        if pos != -1:
                            file_offset = offset + pos
                            logger.info(f"Found {file_type} signature at offset {file_offset}")

                            # Attempt to carve the file
                            carved_file = self._carve_file(
                                disk,
                                file_offset,
                                sig_info,
                                output_dir,
                                file_type
                            )

                            if carved_file:
                                recovered.append(carved_file)

                offset += len(buffer)
                buffer = disk.read(self.chunk_size * 1024)

        logger.info(f"Recovery complete. Found {len(recovered)} files.")
        self.recovered_files = recovered
        return recovered

    def _carve_file(self, disk, offset: int, sig_info: Dict,
                    output_dir: str, file_type: str) -> Dict:
        """
        Carve a file from disk starting at the given offset.

        Args:
            disk: Open file handle to disk image
            offset: Starting offset of file
            sig_info: File signature information
            output_dir: Output directory
            file_type: Type of file being carved

        Returns:
            Dictionary with recovered file information
        """
        try:
            disk.seek(offset)

            # Read file content
            max_file_size = 100 * 1024 * 1024  # 100MB max
            content = disk.read(max_file_size)

            # Look for footer if defined
            if sig_info['footer']:
                footer_pos = content.find(sig_info['footer'])
                if footer_pos != -1:
                    content = content[:footer_pos + len(sig_info['footer'])]
            else:
                # Use heuristics to determine file size
                content = self._estimate_file_size(content, file_type)

            # Generate unique filename
            file_hash = hashlib.md5(content[:1024]).hexdigest()[:8]
            filename = f"recovered_{file_type}_{offset}_{file_hash}{sig_info['extension']}"
            output_path = os.path.join(output_dir, filename)

            # Write recovered file
            with open(output_path, 'wb') as f:
                f.write(content)

            file_info = {
                'type': file_type,
                'offset': offset,
                'size': len(content),
                'path': output_path,
                'hash_md5': hashlib.md5(content).hexdigest(),
                'hash_sha256': hashlib.sha256(content).hexdigest()
            }

            logger.info(f"Carved file: {filename} ({len(content)} bytes)")
            return file_info

        except Exception as e:
            logger.error(f"Error carving file at offset {offset}: {e}")
            return None

    def _estimate_file_size(self, content: bytes, file_type: str) -> bytes:
        """
        Estimate file size for formats without clear footer markers.
        Uses heuristics based on file type.
        """
        # Simple heuristic: look for long runs of null bytes
        null_threshold = 4096  # 4KB of nulls indicates end

        for i in range(len(content) - null_threshold):
            if content[i:i+null_threshold] == b'\x00' * null_threshold:
                return content[:i]

        return content

    def recover_from_unallocated_space(self, device_path: str,
                                       output_dir: str) -> List[Dict]:
        """
        Recover files from unallocated disk space.

        Args:
            device_path: Path to device or partition
            output_dir: Output directory for recovered files

        Returns:
            List of recovered files
        """
        logger.info(f"Scanning unallocated space on {device_path}")
        return self.scan_disk_image(device_path, output_dir)

    def generate_recovery_report(self, output_path: str) -> None:
        """
        Generate a detailed report of recovered files.

        Args:
            output_path: Path to save the report
        """
        if not self.recovered_files:
            logger.warning("No recovered files to report")
            return

        with open(output_path, 'w') as report:
            report.write("=" * 80 + "\n")
            report.write("FILE RECOVERY REPORT\n")
            report.write("=" * 80 + "\n\n")

            report.write(f"Total Files Recovered: {len(self.recovered_files)}\n\n")

            # Group by file type
            by_type = {}
            for file_info in self.recovered_files:
                file_type = file_info['type']
                if file_type not in by_type:
                    by_type[file_type] = []
                by_type[file_type].append(file_info)

            report.write("Files by Type:\n")
            report.write("-" * 80 + "\n")
            for file_type, files in by_type.items():
                total_size = sum(f['size'] for f in files)
                report.write(f"{file_type.upper()}: {len(files)} files ({total_size:,} bytes)\n")

            report.write("\n" + "=" * 80 + "\n")
            report.write("DETAILED FILE LISTING\n")
            report.write("=" * 80 + "\n\n")

            for i, file_info in enumerate(self.recovered_files, 1):
                report.write(f"File #{i}\n")
                report.write(f"  Type: {file_info['type']}\n")
                report.write(f"  Offset: {file_info['offset']} (0x{file_info['offset']:X})\n")
                report.write(f"  Size: {file_info['size']:,} bytes\n")
                report.write(f"  Path: {file_info['path']}\n")
                report.write(f"  MD5: {file_info['hash_md5']}\n")
                report.write(f"  SHA256: {file_info['hash_sha256']}\n")
                report.write("\n")

        logger.info(f"Recovery report saved to {output_path}")


def main():
    """Example usage of FileRecoveryTool"""
    import argparse

    parser = argparse.ArgumentParser(description='File Recovery Tool')
    parser.add_argument('--image', required=True, help='Disk image path')
    parser.add_argument('--output', required=True, help='Output directory')
    parser.add_argument('--report', help='Report output path')

    args = parser.parse_args()

    tool = FileRecoveryTool()
    recovered = tool.scan_disk_image(args.image, args.output)

    if args.report:
        tool.generate_recovery_report(args.report)

    print(f"\n✓ Recovery complete: {len(recovered)} files recovered")


if __name__ == '__main__':
    main()
