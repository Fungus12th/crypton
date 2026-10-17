import struct
import time
from dataclasses import dataclass
from typing import Optional

MAGIC = b"CRYPTON1"  # 8 bytes
HEADER_V1_FMT = ">8s16sIII12s48sd"
# Layout:
# 8s  : Magic (b"CRYPTON1")
# 16s : Salt (16 bytes)
# I   : Time cost (uint32)
# I   : Memory cost in KB (uint32)
# I   : Parallelism lanes (uint32)
# 12s : Nonce for MVK wrapping (12 bytes)
# 48s : Wrapped MVK (32 bytes key + 16 bytes GCM tag)
# d   : Creation Unix timestamp (float64)
HEADER_BASE_SIZE = struct.calcsize(HEADER_V1_FMT)


@dataclass
class VaultHeader:
    salt: bytes
    time_cost: int
    memory_cost: int
    parallelism: int
    mvk_nonce: bytes
    wrapped_mvk: bytes
    created_at: float
    wrapped_cloud_token: Optional[bytes] = None

    def serialize(self) -> bytes:
        """Pack vault header into binary format."""
        base = struct.pack(
            HEADER_V1_FMT,
            MAGIC,
            self.salt,
            self.time_cost,
            self.memory_cost,
            self.parallelism,
            self.mvk_nonce,
            self.wrapped_mvk,
            self.created_at,
        )
        if self.wrapped_cloud_token:
            # Append 4-byte length + payload
            token_len = len(self.wrapped_cloud_token)
            base += struct.pack(">I", token_len) + self.wrapped_cloud_token
        else:
            base += struct.pack(">I", 0)
        return base

    @classmethod
    def deserialize(cls, data: bytes) -> "VaultHeader":
        """Unpack vault header from binary format."""
        if len(data) < HEADER_BASE_SIZE + 4:
            raise ValueError("Corrupted vault header: file size too small.")

        magic, salt, time_cost, mem_cost, parallelism, mvk_nonce, wrapped_mvk, created_at = (
            struct.unpack(HEADER_V1_FMT, data[:HEADER_BASE_SIZE])
        )

        if magic != MAGIC:
            raise ValueError(f"Invalid vault signature: {magic!r} (expected {MAGIC!r})")

        offset = HEADER_BASE_SIZE
        (token_len,) = struct.unpack(">I", data[offset : offset + 4])
        offset += 4

        wrapped_cloud_token = None
        if token_len > 0:
            if len(data) < offset + token_len:
                raise ValueError("Corrupted vault header: truncated cloud token payload.")
            wrapped_cloud_token = data[offset : offset + token_len]

        return cls(
            salt=salt,
            time_cost=time_cost,
            memory_cost=mem_cost,
            parallelism=parallelism,
            mvk_nonce=mvk_nonce,
            wrapped_mvk=wrapped_mvk,
            created_at=created_at,
            wrapped_cloud_token=wrapped_cloud_token,
        )
