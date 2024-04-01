import os
import sys
import struct
import time
from typing import Generator, Literal

MODULO = 2**32
MASK = MODULO - 1
CRYPT_KEY = 0x3716f028
NUTS = (
    "kr.nut",
    "kfunc.nut",
    "kio.nut",
    "kgeom.nut",
    "kar.nut",
    "kgl.nut",
    "kglscript.nut",
    "kglefx.nut",
    "kwt.nut",
    "kwtcomponents.nut",
    "kgl2d.nut",
    "kglscene.nut",
    "kserializer.nut",
    "serialize_state.nut"  # Not included in older versions
)


class KotoriChan:
    def __init__(self, path: str):
        self.path = path

    def pack(self):
        start_time = time.time()
        base_nuts = [name for name in NUTS if os.path.isfile(os.path.join(self.path, name))]
        extra_nuts = [name for name in os.listdir(self.path) if name not in NUTS and name.endswith(".nut")]
        nut_names = [*base_nuts, *extra_nuts]
        named_nuts: list[tuple[str, bytes]] = []
        for nut_name in nut_names:
            nut_path = os.path.join(self.path, nut_name)
            with open(nut_path, "rb") as file:
                named_nuts.append((nut_name, file.read()))
        nuts = []
        for nut in self.packed_nut_generator(named_nuts):
            nuts.append(nut)
        unencrypted_pnut = b"".join(nuts)
        bb = BiBiuffer(unencrypted_pnut)
        bb.crypt(CRYPT_KEY)
        encrypted_pnut = bb.data
        output_path = os.path.join(os.path.dirname(self.path), "kotori.pnut")
        with open(output_path, "wb") as file:
            file.write(encrypted_pnut)
        elapsed_time = time.time() - start_time
        print(f"Successfully packed to \"{output_path}\" (Took {round(elapsed_time, 3)}s)")

    def unpack(self):
        start_time = time.time()
        with open(self.path, "rb") as file:
            encrypted_data = file.read()
        bb = BiBiuffer(encrypted_data)
        bb.crypt(CRYPT_KEY)
        decrypted_data = bb.data
        output_dir = os.path.join(os.path.dirname(self.path), "kotori")
        os.makedirs(output_dir, exist_ok=True)
        extracted_names = []
        for name, src in self.unpacked_nut_generator(decrypted_data):
            output_path = os.path.join(output_dir, name)
            with open(output_path, "wb") as nut:
                nut.write(src)
                extracted_names.append(name)
        elapsed_time = time.time() - start_time
        print(f"Successfully unpacked to \"{output_dir}\" (Took {round(elapsed_time, 3)}s)")
        preexisting_files = [name for name in os.listdir(output_dir) if name not in extracted_names and not os.path.isdir(os.path.join(output_dir, name))]
        if preexisting_files:
            print(f"Warning: Found pre-existing files in the output directory not associated with this unpack:\n{preexisting_files}")
            remove = self.get_yes_no_input("Would you like to remove them?", default="n")
            if remove:
                for name in preexisting_files:
                    file_to_remove = os.path.join(output_dir, name)
                    os.remove(file_to_remove)
                print("Successfully deleted unassociated files!")

    def packed_nut_generator(self, named_nuts: list[tuple[str, bytes]]) -> Generator[bytes, None, None]:
        for name, src in named_nuts:
            name_length = len(name)
            name_length_bytes = struct.pack(">H", name_length)
            src_length = len(src)
            src_length_bytes = struct.pack(">H", src_length)
            nut = name_length_bytes + name.encode() + src_length_bytes + src
            print(f"Packed \"{name}\" (length: {src_length})")
            yield nut

    def unpacked_nut_generator(self, data: bytes) -> Generator[tuple[str, bytes], None, None]:
        bb = BiBiuffer(data)
        while bb.pos < len(data):
            name_length = int.from_bytes(bb.get(2))
            name = bb.get(name_length).decode()
            src_length = int.from_bytes(bb.get(2))
            src = bb.get(src_length)
            print(f"Unpacked \"{name}\" (length: {src_length})" + (" (Overwriting)" if os.path.isfile(os.path.join(os.path.dirname(self.path), "kotori", name)) else ""))
            yield name, src

    @staticmethod
    def get_yes_no_input(prompt: str, default: Literal["y", "n"] = "y") -> bool:
        while True:
            prompt_with_default = prompt + (" (Y/n): " if default.lower() == 'y' else " (y/N): ")
            user_input = input(prompt_with_default).strip().lower()
            if not user_input:
                user_input = default
            if user_input in ['y', 'yes']:
                return True
            elif user_input in ['n', 'no']:
                return False
            else:
                print("Invalid input. Please enter 'y' or 'n'.")


class BiBiuffer:
    def __init__(self, data: bytes = None):
        self.data = data

        self.pos = 0

    def get(self, length: int) -> bytes:
        data = self.data[self.pos:self.pos + length]
        self.pos += length
        return data

    def put(self, data: bytes):
        self.data = self.data[:self.pos] + data + self.data[self.pos:]
        self.pos += len(data)

    def crypt(self, magic: int):
        data_array = bytearray(self.data)
        i = 0
        while i < len(data_array):
            if (i % 4 == 0) and (i > 0):
                magic = ((magic * 2) & MASK) | (((~((magic >> 3) ^ magic)) & MASK) >> 0x0D) & 1
            if (i + 4) < len(data_array):
                data_segment = int.from_bytes(data_array[i:i + 4], byteorder="little")
                data_segment ^= magic
                data_array[i:i + 4] = data_segment.to_bytes(4, byteorder="little")
                i += 4
            else:
                magic_mod = magic >> (8 * (i % 4)) & 0xFF
                single_byte = data_array[i]
                single_byte ^= magic_mod
                data_array[i] = single_byte
                i += 1
        self.data = bytes(data_array)


def main():
    if len(sys.argv) != 3 or len(sys.argv) > 1 and sys.argv[1] in {"help", "--help", "-h"} or sys.argv[1] not in {"pack", "unpack"}:
        print("Usage: python kotorichan.py <pack|unpack> <path>")
        print("- pack: Takes a kotori/ directory <path> argument and packs it into a kotori.pnut file next to kotori/")
        print("- unpack: Takes a kotori.pnut file <path> argument and unpacks it into a kotori/ directory next to kotori.pnut")
        print("Warning: Be careful as output will overwrite existing file(s)")
        sys.exit(1)
    command = sys.argv[1]
    path = os.path.abspath(sys.argv[2])
    kc = KotoriChan(path)
    match command:
        case "pack":
            if not os.path.isdir(path):
                raise FileNotFoundError(f"Error: kotori directory not found \"{path}\"")
            kc.pack()
        case "unpack":
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Error: kotori.pnut file not found \"{path}\"")
            kc.unpack()


if __name__ == "__main__":
    main()
