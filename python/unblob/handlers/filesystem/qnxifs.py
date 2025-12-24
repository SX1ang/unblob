from ...models import File, HexString, StructHandler, ValidChunk
from ...extractors import Command
from unblob.file_utils import InvalidInputFormat
from typing import Optional
from pathlib import Path
from structlog import get_logger

logger = get_logger()

custum_tools = Path(__file__).parent.parent.parent / "custum_tools"
ifs_extractor = str(custum_tools / "dumpifs")

class QNXIFSHandler(StructHandler):
    NAME = "qnxifs"
    PATTERNS = [
        # 'imagefs.' is the magic string for QNXIFS
        HexString("69 6d 61 67 65 66 73 04")
    ]

    C_DEFINITIONS = r"""
        struct imagefs_header {
            char magic[8];
        }
    """
    HEADER_STRUCT = "imagefs_header"
    
    
    EXTRACTOR = Command(ifs_extractor, "{inpath}", "-d", "{outdir}")

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        
        #返回一个ValidChunk对象，从start_offset开始到文件末尾都是有效的
        return ValidChunk(
            start_offset=start_offset,
            end_offset=file.size(),
        )