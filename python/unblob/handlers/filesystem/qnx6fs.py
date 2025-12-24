from ...models import File, HexString, StructHandler, ValidChunk
from ...extractors import Command
from unblob.file_utils import InvalidInputFormat
from typing import Optional
from pathlib import Path
from structlog import get_logger

logger = get_logger()

MAGIC = 0x68191122  # Magic number for QNX6FS

custum_tools = Path(__file__).parent.parent.parent / "custum_tools"
qnx6_extractor = str(custum_tools / "qnx6_extractor.py")

class QNX6FSHandler(StructHandler):
    NAME = "qnx6fs"

    PATTERNS = [HexString("22 11 19 68")]

    C_DEFINITIONS = r"""
        typedef struct qnx6_superblock {
            uint32 magic;
            uint32 checksum;
            uint64 serial;
            uint32 ctime;
            uint32 atime;
            uint32 flags;
            uint16 version1;
            uint16 version2;
            uint8 volumeid[16];
            uint32 blocksize;
            uint32 num_inodes;
            uint32 free_inodes;
            uint32 num_blocks;
            uint32 free_blocks;
            uint32 allocgroup;
    } qnx6_superblock_t;
    """
    
    HEADER_STRUCT = "qnx6_superblock_t"
    
    EXTRACTOR = Command("python3", qnx6_extractor, "{inpath}", "{outdir}")

    def valid_header(self, header) -> bool:
        if header.blocksize not in [512, 1024, 2048, 4096, 8192]:
            logger.debug("Invalid blocksize in QNX6FS header", blocksize=header.blocksize)
            return False
        if header.num_blocks == 0 or header.num_inodes == 0:
            logger.debug("Invalid number of blocks or inodes in QNX6FS header", num_blocks=header.num_blocks, num_inodes=header.num_inodes)
            return False
        return True

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        header = self.parse_header(file)

        if not self.valid_header(header):
            raise InvalidInputFormat("Invalid QNX6FS header.")
        
        #返回一个ValidChunk对象，表示整个文件都是有效的，因为qnx6解包工具需要整个文件
        return ValidChunk(
            start_offset=0,
            end_offset=file.size(),
        )