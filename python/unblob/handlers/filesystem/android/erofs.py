import io
from typing import Optional

from unblob.extractors import Command
from unblob.file_utils import (
    Endian,
    InvalidInputFormat,
    snull,
)
from unblob.models import (
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct erofs_handler{
        uint32 magic;
        uint32 crc32c;
        uint32 feature_compact;
        uint8  block_size_bs;
        uint8  sb_extslots;
        uint16 root_nid;
        uint64 inos;
        uint64 build_time;
        uint32 build_time_nsec;
        uint32 block_count;
        uint32 meta_blkaddr;
        uint32 xattr_blkaddr;
        uint8  uuid[16];
        char   volume_name[16];
        uint32 feature_incompact;
        char   reserved[44];
    } erofs_handler_t;
"""

SUPERBLOCK_OFFSET = 0x400


class EROFSHandler(StructHandler):
    NAME = "erofs"
    PATTERNS = [HexString("e2 e1 f5 e0")]  # Magic in little endian
    HEADER_STRUCT = "erofs_handler_t"
    C_DEFINITIONS = C_DEFINITIONS
    EXTRACTOR = Command(
        "fsck.erofs",
        "--no-preserve",
        "--extract={outdir}",
        "{inpath}",
    )
    PATTERN_MATCH_OFFSET = -SUPERBLOCK_OFFSET

    DOC = HandlerDoc(
        name="Android EROFS",
        description="EROFS (Enhanced Read-Only File System) is a lightweight, high-performance file system designed for read-only use cases, commonly used in Android and Linux. It features compression support, metadata efficiency, and a fixed superblock structure.",
        handler_type=HandlerType.FILESYSTEM,
        vendor="Google",
        references=[
            Reference(
                title="EROFS Documentation",
                url="https://www.kernel.org/doc/html/latest/filesystems/erofs.html",
            ),
            Reference(
                title="EROFS Wikipedia",
                url="https://en.wikipedia.org/wiki/Enhanced_Read-Only_File_System",
            ),
        ],
        limitations=[],
    )

    def is_valid_header(self, header) -> bool:
        try:
            snull(header.volume_name).decode("utf-8")
        except UnicodeDecodeError:
            return False
        return (
            header.block_count >= 1
            and header.build_time > 0
            and header.build_time_nsec > 0
            and header.block_size_bs >= 9
        )

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        file.seek(start_offset + SUPERBLOCK_OFFSET, io.SEEK_SET)
        header = self.parse_header(file, Endian.LITTLE)
        if not self.is_valid_header(header):
            raise InvalidInputFormat("Invalid erofs header.")

        end_offset = (1 << header.block_size_bs) * header.block_count
        return ValidChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )
