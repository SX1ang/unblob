from typing import Optional
from structlog import get_logger

from unblob.file_utils import InvalidInputFormat

from ...extractors import Command
from ...models import File, HexString, StructHandler, ValidChunk, Extractor

logger = get_logger()

F2FS_MAGIC_OFFSET = 0x400  # 1024 bytes
F2FS_MAGIC = 0xF2F52010

class F2FSHandler(StructHandler):
    NAME = "f2fs"

    # F2FS magic: 0xF2F52010 in little-endian
    PATTERNS = [HexString("10 20 f5 f2")]

    EXTRACTOR = Command(
        "sudo", "bash", "-c",
        'TMPDIR=$(mktemp -d) && '
        'mount -t f2fs -o loop,ro "{inpath}" "$TMPDIR" && '
        'cp -a "$TMPDIR"/. "{outdir}" ; '
        'chown -R $SUDO_UID:$SUDO_GID  "{outdir}" ; '
        'umount "$TMPDIR" ; '
        'rmdir "$TMPDIR"'
    )

    C_DEFINITIONS = r"""
        typedef struct f2fs_super_block {
            char blank[0x400];                 // Not part of spec, magic is at 0x400
            uint32 magic;                      /* Magic Number */
            uint16 major_ver;                  /* Major Version */
            uint16 minor_ver;                  /* Minor Version */
            uint32 log_sectorsize;             /* log2 sector size in bytes */
            uint32 log_sectors_per_block;      /* log2 # of sectors per block */
            uint32 log_blocksize;              /* log2 block size in bytes */
            uint32 log_blocks_per_seg;         /* log2 # of blocks per segment */
            uint32 segs_per_sec;               /* # of segments per section */
            uint32 secs_per_zone;              /* # of sections per zone */
            uint32 checksum_offset;            /* checksum offset inside super block */
            uint64 block_count;                /* total # of user blocks */
        } f2fs_super_block_t;
    """
    HEADER_STRUCT = "f2fs_super_block_t"

    # Pattern matches at 0x400, but chunk starts at 0
    PATTERN_MATCH_OFFSET = -F2FS_MAGIC_OFFSET

    def valid_header(self, header) -> bool:
        if header.magic != F2FS_MAGIC:
            logger.debug("F2FS magic number mismatch", magic=hex(header.magic))
            return False
        
        if header.major_ver > 10:  # Sanity check
            logger.debug("F2FS major version too high", major_ver=header.major_ver)
            return False
            
        if header.log_blocksize > 16:  # Block size shouldn't exceed 64MB
            logger.debug(
                "F2FS log_blocksize too large", 
                log_blocksize=header.log_blocksize
            )
            return False
            
        if header.block_count == 0:
            logger.debug("F2FS block count is zero")
            return False
            
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)
        
        if not self.valid_header(header):
            raise InvalidInputFormat("Invalid F2FS header.")
        
        # Calculate filesystem size
        block_size = 1 << header.log_blocksize
        total_size = header.block_count * block_size
        
        return ValidChunk(
            start_offset=start_offset,
            end_offset=start_offset + total_size,
        )

