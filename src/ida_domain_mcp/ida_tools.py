import sys

if sys.version_info < (3, 11):
    raise RuntimeError("Python 3.11 or higher is required for the MCP plugin")

import re
import struct
from typing import (
    TypedDict,
    Optional,
    Annotated,
    TypeVar,
    Generic,
    NotRequired,
    overload,
    Literal,
)

# A module that helps with writing thread safe ida code.
# Based on:
# https://web.archive.org/web/20160305190440/http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator/
import logging
import queue
import functools
from enum import IntEnum

from ida_domain import Database
from ida_domain.database import IdaCommandOptions
from ida_domain.segments import Segments
from ida_domain.bytes import Bytes
from ida_domain.functions import Functions
from ida_domain.instructions import Instructions
import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_lines
import ida_idaapi
import idc
import idaapi
import idautils
import ida_nalt
import ida_bytes
import ida_typeinf
import ida_xref
import ida_entry

# import ida_idd
# import ida_dbg
# import ida_name
import ida_ida
import ida_frame
import ida_segment

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))


class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


# Important note: Always make sure the return value from your function f is a
# copy of the data you have gotten from IDA, and not the original data.
#
# Example:
# --------
#
# Do this:
#
#   @idaread
#   def ts_Functions():
#       return list(idautils.Functions())
#
# Don't do this:
#
#   @idaread
#   def ts_Functions():
#       return idautils.Functions()
#

logger = logging.getLogger(__name__)


# Enum for safety modes. Higher means safer:
class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


call_stack = queue.LifoQueue()


def sync_wrapper(ff, safety_mode: IDASafety):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    # logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = "Invalid safety mode {} over function {}".format(
            safety_mode, ff.__name__
        )
        logger.error(error_str)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = queue.Queue()

    def runned():
        # logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = (
                "Call stack is not empty while calling the " "function {} from {}"
            ).format(ff.__name__, last_func_name)
            # logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()
            # logger.debug('Finished runned')

    idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res


def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__  # type: ignore
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper


def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__  # type: ignore
        return sync_wrapper(ff, idaapi.MFF_READ)

    return wrapper


def is_window_active():
    """Returns whether IDA is currently active"""
    # Source: https://github.com/mrexodia/ida-pro-mcp/blob/fea2eb6a9e41a44fdb0dd9507ce7a29ef6124a75/src/ida_pro_mcp/ida_mcp/sync.py#L108C5-L109C75
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    try:
        if using_pyside6:
            import PySide6.QtWidgets as QApplication
        else:
            import PyQt5.QtWidgets as QApplication

        app = QApplication.instance()
        if app is None:
            return False

        for widget in app.topLevelWidgets():
            if widget.isActiveWindow():
                return True
    except Exception:
        # Headless mode or other error (this is not a critical feature)
        pass
    return False


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


def get_image_size() -> int:
    try:
        # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
        info = idaapi.get_inf_structure()  # type: ignore
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida

        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    # Bad heuristic for image size (bad if the relocations are the last section)
    image_size = omax_ea - omin_ea
    # Try to extract it from the PE header
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


@idaread
def get_metadata() -> Metadata:
    """Get metadata about the current IDB"""

    # Fat Mach-O binaries can return a None hash:
    # https://github.com/mrexodia/ida-pro-mcp/issues/26
    def hash(f):
        try:
            return f().hex()
        except:
            return ""

    return Metadata(
        path=idaapi.get_input_file_path(),
        module=idaapi.get_root_filename(),
        base=hex(idaapi.get_imagebase()),
        size=hex(get_image_size()),
        md5=hash(ida_nalt.retrieve_input_file_md5),
        sha256=hash(ida_nalt.retrieve_input_file_sha256),
        crc32=hex(ida_nalt.retrieve_input_file_crc32()),
        filesize=hex(ida_nalt.retrieve_input_file_size()),
    )


def get_prototype(fn: ida_funcs.func_t) -> Optional[str]:
    try:
        prototype: ida_typeinf.tinfo_t = fn.get_prototype()
        if prototype is not None:
            return str(prototype)
        else:
            return None
    except AttributeError:
        try:
            return idc.get_type(fn.start_ea)
        except:
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, fn.start_ea):
                return str(tif)
            return None
    except Exception as e:
        print(f"Error getting function prototype: {e}")
        return None


class Function(TypedDict):
    address: str
    name: str
    size: str


def parse_address(address: str | int) -> int:
    if isinstance(address, int):
        return address
    try:
        return int(address, 0)
    except ValueError:
        for ch in address:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {address}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {address}")


@overload
def get_function(address: int, *, raise_error: Literal[True]) -> Function: ...


@overload
def get_function(address: int) -> Function: ...


@overload
def get_function(
    address: int, *, raise_error: Literal[False]
) -> Optional[Function]: ...


def get_function(address, *, raise_error=True):
    fn = idaapi.get_func(address)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(address)}")
        return None

    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)

    return Function(address=hex(address), name=name, size=hex(fn.end_ea - fn.start_ea))


DEMANGLED_TO_EA = {}


def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        # Get the function name and demangle it
        # MNG_NODEFINIT inhibits everything except the main name
        # where default demangling adds the function signature
        # and decorators (if any)
        demangled = idaapi.demangle_name(idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    # 8-bit integers
    if type_name in ("int8", "__int8", "int8_t", "char", "signed char"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT8)
    elif type_name in ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT8)

    # 16-bit integers
    elif type_name in (
        "int16",
        "__int16",
        "int16_t",
        "short",
        "short int",
        "signed short",
        "signed short int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT16)
    elif type_name in (
        "uint16",
        "__uint16",
        "uint16_t",
        "unsigned short",
        "unsigned short int",
        "word",
        "WORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT16)

    # 32-bit integers
    elif type_name in (
        "int32",
        "__int32",
        "int32_t",
        "int",
        "signed int",
        "long",
        "long int",
        "signed long",
        "signed long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
    elif type_name in (
        "uint32",
        "__uint32",
        "uint32_t",
        "unsigned int",
        "unsigned long",
        "unsigned long int",
        "dword",
        "DWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)

    # 64-bit integers
    elif type_name in (
        "int64",
        "__int64",
        "int64_t",
        "long long",
        "long long int",
        "signed long long",
        "signed long long int",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT64)
    elif type_name in (
        "uint64",
        "__uint64",
        "uint64_t",
        "unsigned int64",
        "unsigned long long",
        "unsigned long long int",
        "qword",
        "QWORD",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT64)

    # 128-bit integers
    elif type_name in ("int128", "__int128", "int128_t", "__int128_t"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_INT128)
    elif type_name in (
        "uint128",
        "__uint128",
        "uint128_t",
        "__uint128_t",
        "unsigned int128",
    ):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT128)

    # Floating point types
    elif type_name in ("float",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_FLOAT)
    elif type_name in ("double",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_DOUBLE)
    elif type_name in ("long double", "ldouble"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_LDOUBLE)

    # Boolean type
    elif type_name in ("bool", "_Bool", "boolean"):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_BOOL)

    # Void type
    elif type_name in ("void",):
        return ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)

    # If not a standard type, try to get a named type
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, type_name, ida_typeinf.BTF_STRUCT):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_TYPEDEF):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_ENUM):
        return tif

    if tif.get_named_type(None, type_name, ida_typeinf.BTF_UNION):
        return tif

    if tif := ida_typeinf.tinfo_t(type_name):
        return tif

    raise IDAError(f"Unable to retrieve {type_name} type info object")


@idaread
def get_function_by_name(
    name: Annotated[str, "Name of the function to get"],
) -> Function:
    """Get a function by its name"""
    function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
    if function_address == idaapi.BADADDR:
        # If map has not been created yet, create it
        if len(DEMANGLED_TO_EA) == 0:
            create_demangled_to_ea_map()
        # Try to find the function in the map, else raise an error
        if name in DEMANGLED_TO_EA:
            function_address = DEMANGLED_TO_EA[name]
        else:
            raise IDAError(f"No function found with name {name}")
    return get_function(function_address)


@idaread
def get_function_by_address(
    address: Annotated[str, "Address of the function to get"],
) -> Function:
    """Get a function by its address"""
    return get_function(parse_address(address))


@idaread
def get_current_address() -> str:
    """Get the address currently selected by the user"""
    return hex(idaapi.get_screen_ea())


@idaread
def get_current_function() -> Optional[Function]:
    """Get the function currently selected by the user"""
    return get_function(idaapi.get_screen_ea())


class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str


def convert_number(
    text: Annotated[str, "Textual representation of the number to convert"],
    size: Annotated[Optional[int], "Size of the variable in bytes"],
) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    try:
        value = int(text, 0)
    except ValueError:
        raise IDAError(f"Invalid number: {text}")

    # Estimate the size of the number
    if not size:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    # Convert the number to bytes
    try:
        bytes = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        raise IDAError(f"Number {text} is too big for {size} bytes")

    # Convert the bytes to ASCII
    ascii = ""
    for byte in bytes.rstrip(b"\x00"):
        if byte >= 32 and byte <= 126:
            ascii += chr(byte)
        else:
            ascii = None
            break

    return ConvertedNumber(
        decimal=str(value),
        hexadecimal=hex(value),
        bytes=bytes.hex(" "),
        ascii=ascii,
        binary=bin(value),
    )


T = TypeVar("T")


class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset : offset + count],
        "next_offset": next_offset,
    }


def pattern_filter(data: list[T], pattern: str, key: str) -> list[T]:
    if not pattern:
        return data

    regex = None

    # Parse /regex/ or /regex/flags syntax
    if pattern.startswith("/") and pattern.count("/") >= 2:
        last_slash = pattern.rfind("/")
        body = pattern[1:last_slash]
        flag_str = pattern[last_slash + 1 :]

        flags = 0
        for ch in flag_str:
            if ch == "i":
                flags |= re.IGNORECASE
            elif ch == "m":
                flags |= re.MULTILINE
            elif ch == "s":
                flags |= re.DOTALL
            # ignore other flags for now

        try:
            regex = re.compile(body, flags or re.IGNORECASE)
        except re.error:
            regex = None

    def get_value(item) -> str:
        try:
            v = item[key]
        except Exception:
            v = getattr(item, key, "")
        return "" if v is None else str(v)

    def matches(item) -> bool:
        text = get_value(item)
        if regex is not None:
            return bool(regex.search(text))
        # straigthforward mode: case-insensitive contains
        return pattern.lower() in text.lower()

    return [item for item in data if matches(item)]


@idaread
def list_functions_filter(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of functions to list (100 is a good default, 0 means remainder)"
    ],
    filter: Annotated[
        str,
        "Filter to apply to the list (required parameter, empty string for no filter). Case-insensitive contains or /regex/ syntax",
    ],
) -> Page[Function]:
    """List matching functions in the database (paginated, filtered)"""
    functions = [get_function(address) for address in idautils.Functions()]
    functions = pattern_filter(functions, filter, "name")
    return paginate(functions, offset, count)


def list_functions(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of functions to list (100 is a good default, 0 means remainder)"
    ],
) -> Page[Function]:
    """List all functions in the database (paginated)"""
    return list_functions_filter(offset, count, "")


class Global(TypedDict):
    address: str
    name: str


@idaread
def list_globals_filter(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of globals to list (100 is a good default, 0 means remainder)"
    ],
    filter: Annotated[
        str,
        "Filter to apply to the list (required parameter, empty string for no filter). Case-insensitive contains or /regex/ syntax",
    ],
) -> Page[Global]:
    """List matching globals in the database (paginated, filtered)"""
    globals: list[Global] = []
    for addr, name in idautils.Names():
        # Skip functions and none
        if not idaapi.get_func(addr) or name is None:
            globals += [Global(address=hex(addr), name=name)]

    globals = pattern_filter(globals, filter, "name")
    return paginate(globals, offset, count)


def list_globals(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of globals to list (100 is a good default, 0 means remainder)"
    ],
) -> Page[Global]:
    """List all globals in the database (paginated)"""
    return list_globals_filter(offset, count, "")


class Import(TypedDict):
    address: str
    imported_name: str
    module: str


@idaread
def list_imports(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of imports to list (100 is a good default, 0 means remainder)"
    ],
) -> Page[Import]:
    """List all imported symbols with their name and module (paginated)"""
    nimps = ida_nalt.get_import_module_qty()

    rv = []
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f"#{ordinal}"

            acc += [
                Import(address=hex(ea), imported_name=symbol_name, module=module_name)
            ]

            return True

        imp_cb_w_context = lambda ea, symbol_name, ordinal: imp_cb(
            ea, symbol_name, ordinal, rv
        )
        ida_nalt.enum_import_names(i, imp_cb_w_context)

    return paginate(rv, offset, count)


class String(TypedDict):
    address: str
    length: int
    string: str


@idaread
def list_strings_filter(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of strings to list (100 is a good default, 0 means remainder)"
    ],
    filter: Annotated[
        str,
        "Filter to apply to the list (required parameter, empty string for no filter). Case-insensitive contains or /regex/ syntax",
    ],
) -> Page[String]:
    """List matching strings in the database (paginated, filtered)"""
    strings: list[String] = []
    for item in idautils.Strings():
        if item is None:
            continue
        try:
            string = str(item)
            if string:
                strings += [
                    String(address=hex(item.ea), length=item.length, string=string),
                ]
        except:
            continue
    strings = pattern_filter(strings, filter, "string")
    return paginate(strings, offset, count)


def list_strings(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[
        int, "Number of strings to list (100 is a good default, 0 means remainder)"
    ],
) -> Page[String]:
    """List all strings in the database (paginated)"""
    return list_strings_filter(offset, count, "")


class Segment(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


def ida_segment_perm2str(perm: int) -> str:
    perms = []
    if perm & ida_segment.SEGPERM_READ:
        perms.append("r")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_WRITE:
        perms.append("w")
    else:
        perms.append("-")
    if perm & ida_segment.SEGPERM_EXEC:
        perms.append("x")
    else:
        perms.append("-")
    return "".join(perms)


@idaread
def list_segments() -> list[Segment]:
    """List all segments in the binary."""
    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        segments.append(
            Segment(
                name=seg_name,
                start=hex(seg.start_ea),
                end=hex(seg.end_ea),
                size=hex(seg.end_ea - seg.start_ea),
                permissions=ida_segment_perm2str(seg.perm),
            )
        )
    return segments


@idaread
def list_local_types():
    """List all Local types in the database"""
    error = ida_hexrays.hexrays_failure_t()
    locals = []
    idati = ida_typeinf.get_idati()
    type_count = ida_typeinf.get_ordinal_limit(idati)
    for ordinal in range(1, type_count):
        try:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(idati, ordinal):
                type_name = tif.get_type_name()
                if not type_name:
                    type_name = f"<Anonymous Type #{ordinal}>"
                locals.append(f"\nType #{ordinal}: {type_name}")
                if tif.is_udt():
                    c_decl_flags = (
                        ida_typeinf.PRTYPE_MULTI
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI
                        | ida_typeinf.PRTYPE_DEF
                        | ida_typeinf.PRTYPE_METHODS
                        | ida_typeinf.PRTYPE_OFFSETS
                    )
                    c_decl_output = tif._print(None, c_decl_flags)
                    if c_decl_output:
                        locals.append(f"  C declaration:\n{c_decl_output}")
                else:
                    simple_decl = tif._print(
                        None,
                        ida_typeinf.PRTYPE_1LINE
                        | ida_typeinf.PRTYPE_TYPE
                        | ida_typeinf.PRTYPE_SEMI,
                    )
                    if simple_decl:
                        locals.append(f"  Simple declaration:\n{simple_decl}")
            else:
                message = f"\nType #{ordinal}: Failed to retrieve information."
                if error.str:
                    message += f": {error.str}"
                if error.errea != idaapi.BADADDR:
                    message += f"from (address: {hex(error.errea)})"
                raise IDAError(message)
        except:
            continue
    return locals


def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise IDAError(
                "Decompiler license is not available. Use `disassemble_function` to get the assembly code instead."
            )

        message = f"Decompilation failed at {hex(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc  # type: ignore (this is a SWIG issue)


@idaread
def decompile_function(
    address: Annotated[str, "Address of the function to decompile"],
) -> str:
    """Decompile a function at the given address"""
    start = parse_address(address)
    cfunc = decompile_checked(start)
    if is_window_active():
        ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
    sv = cfunc.get_pseudocode()
    pseudocode = ""
    for i, sl in enumerate(sv):
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t()
        addr = None if i > 0 else cfunc.entry_ea
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):  # type: ignore (IDA SDK type hint wrong)
            dstr: str | None = item.dstr()
            if dstr:
                ds = dstr.split(": ")
                if len(ds) == 2:
                    try:
                        addr = int(ds[0], 16)
                    except ValueError:
                        pass
        line = ida_lines.tag_remove(sl.line)
        if len(pseudocode) > 0:
            pseudocode += "\n"
        if not addr:
            pseudocode += f"/* line: {i} */ {line}"
        else:
            pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"

    return pseudocode


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    address: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[StackFrameVariable]
    lines: list[DisassemblyLine]


@idaread
def disassemble_function(
    start_address: Annotated[str, "Address of the function to disassemble"],
) -> DisassemblyFunction:
    """Get assembly code for a function (API-compatible with older IDA builds)"""
    start = parse_address(start_address)
    func = idaapi.get_func(start)
    if not func:
        raise IDAError(f"No function found at address {hex(start)}")
    if is_window_active():
        ida_kernwin.jumpto(start)

    func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

    lines: list[DisassemblyLine] = []
    for ea in idautils.FuncItems(func.start_ea):
        if ea == idaapi.BADADDR:
            continue

        seg = idaapi.getseg(ea)
        segment: str | None = idaapi.get_segm_name(seg) if seg else None

        label: str | None = idc.get_name(ea, 0)
        if not label or (label == func_name and ea == func.start_ea):
            label = None

        comments: list[str] = []
        c: str | None = idaapi.get_cmt(ea, False)
        if c:
            comments.append(c)
        c = idaapi.get_cmt(ea, True)
        if c:
            comments.append(c)

        mnem: str = idc.print_insn_mnem(ea) or ""
        ops: list[str] = []
        for n in range(8):
            if idc.get_operand_type(ea, n) == idaapi.o_void:
                break
            ops.append(idc.print_operand(ea, n) or "")
        instruction = f"{mnem} {', '.join(ops)}".rstrip()

        line: DisassemblyLine = {"address": hex(ea), "instruction": instruction}
        if segment:
            line["segment"] = segment
        if label:
            line["label"] = label
        if comments:
            line["comments"] = comments
        lines.append(line)

    # prototype and args via tinfo (safe across versions)
    rettype = None
    args: Optional[list[Argument]] = None
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        ftd = ida_typeinf.func_type_data_t()
        if tif.get_func_details(ftd):
            rettype = str(ftd.rettype)
            args = [
                Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                for i, a in enumerate(ftd)
            ]

    out: DisassemblyFunction = {
        "name": func_name,
        "start_ea": hex(func.start_ea),
        "stack_frame": get_stack_frame_variables_internal(func.start_ea, False),
        "lines": lines,
    }
    if rettype:
        out["return_type"] = rettype
    if args is not None:
        out["arguments"] = args
    return out


class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]


@idaread
def get_xrefs_to(
    address: Annotated[str, "Address to get cross references to"],
) -> list[Xref]:
    """Get all cross references to the given address"""
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):  # type: ignore (IDA SDK type hints are incorrect)
        xrefs += [
            Xref(
                address=hex(xref.frm),
                type="code" if xref.iscode else "data",
                function=get_function(xref.frm, raise_error=False),
            )
        ]
    return xrefs


@idaread
def get_xrefs_to_field(
    struct_name: Annotated[str, "Name of the struct (type) containing the field"],
    field_name: Annotated[str, "Name of the field (member) to get xrefs to"],
) -> list[Xref]:
    """Get all cross references to a named struct field (member)"""

    # Get the type library
    til = ida_typeinf.get_idati()
    if not til:
        raise IDAError("Failed to retrieve type library.")

    # Get the structure type info
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
        print(f"Structure '{struct_name}' not found.")
        return []

    # Get The field index
    idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)  # type: ignore (IDA SDK type hints are incorrect)
    if idx == -1:
        print(f"Field '{field_name}' not found in structure '{struct_name}'.")
        return []

    # Get the type identifier
    tid = tif.get_udm_tid(idx)
    if tid == ida_idaapi.BADADDR:
        raise IDAError(
            f"Unable to get tid for structure '{struct_name}' and field '{field_name}'."
        )

    # Get xrefs to the tid
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(tid):  # type: ignore (IDA SDK type hints are incorrect)
        xrefs += [
            Xref(
                address=hex(xref.frm),
                type="code" if xref.iscode else "data",
                function=get_function(xref.frm, raise_error=False),
            )
        ]
    return xrefs


@idaread
def get_callees(
    function_address: Annotated[str, "Address of the function to get callee functions"],
) -> list[dict[str, str]]:
    """Get all the functions called (callees) by the function at function_address"""
    func_start = parse_address(function_address)
    func = idaapi.get_func(func_start)
    if not func:
        raise IDAError(f"No function found containing address {function_address}")
    func_end = idc.find_func_end(func_start)
    callees: list[dict[str, str]] = []
    current_ea = func_start
    while current_ea < func_end:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, current_ea)
        if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            target = idc.get_operand_value(current_ea, 0)
            target_type = idc.get_operand_type(current_ea, 0)
            # check if it's a direct call - avoid getting the indirect call offset
            if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                # in here, we do not use get_function because the target can be external function.
                # but, we should mark the target as internal/external function.
                func_type = (
                    "internal" if idaapi.get_func(target) is not None else "external"
                )
                func_name = idc.get_name(target)
                if func_name is not None:
                    callees.append(
                        {"address": hex(target), "name": func_name, "type": func_type}
                    )
        current_ea = idc.next_head(current_ea, func_end)

    # deduplicate callees
    unique_callee_tuples = {tuple(callee.items()) for callee in callees}
    unique_callees = [dict(callee) for callee in unique_callee_tuples]
    return unique_callees  # type: ignore


@idaread
def get_callers(
    function_address: Annotated[str, "Address of the function to get callers"],
) -> list[Function]:
    """Get all callers of the given address"""
    callers = {}
    for caller_address in idautils.CodeRefsTo(parse_address(function_address), 0):
        # validate the xref address is a function
        func = get_function(caller_address, raise_error=False)
        if not func:
            continue
        # load the instruction at the xref address
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_address)
        # check the instruction is a call
        if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
            continue
        # deduplicate callers by address
        callers[func["address"]] = func

    return list(callers.values())


@idaread
def get_entry_points() -> list[Function]:
    """Get all entry points in the database"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        func = get_function(address, raise_error=False)
        if func is not None:
            result.append(func)
    return result


@idawrite
def set_comment(
    address: Annotated[str, "Address in the function to set the comment for"],
    comment: Annotated[str, "Comment text"],
):
    """Set a comment for a given address in the function disassembly and pseudocode"""
    ea = parse_address(address)

    if not idaapi.set_cmt(ea, comment, False):
        raise IDAError(f"Failed to set disassembly comment at {hex(ea)}")

    if not ida_hexrays.init_hexrays_plugin():
        return

    # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
    # Check if the address corresponds to a line
    try:
        cfunc = decompile_checked(ea)
    except IDAError:
        # Skip decompiler comment if decompilation fails
        return

    # Special case for function entry comments
    if ea == cfunc.entry_ea:
        idc.set_func_cmt(ea, comment, True)
        cfunc.refresh_func_ctext()
        return

    eamap = cfunc.get_eamap()
    if ea not in eamap:
        print(f"Failed to set decompiler comment at {hex(ea)}")
        return
    nearest_ea = eamap[ea][0].ea

    # Remove existing orphan comments
    if cfunc.has_orphan_cmts():
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()

    # Set the comment by trying all possible item types
    tl = idaapi.treeloc_t()
    tl.ea = nearest_ea
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            return
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    print(f"Failed to set decompiler comment at {hex(ea)}")


def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()


def refresh_decompiler_ctext(function_address: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(
        function_address, error, ida_hexrays.DECOMP_WARNINGS
    )
    if cfunc:
        cfunc.refresh_func_ctext()


@idawrite
def rename_local_variable(
    function_address: Annotated[str, "Address of the function containing the variable"],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"],
):
    """Rename a local variable in a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
        raise IDAError(
            f"Failed to rename local variable {old_name} in function {hex(func.start_ea)}"
        )
    refresh_decompiler_ctext(func.start_ea)


@idawrite
def rename_global_variable(
    old_name: Annotated[str, "Current name of the global variable"],
    new_name: Annotated[
        str, "New name for the global variable (empty for a default name)"
    ],
):
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError(f"Failed to rename global variable {old_name} to {new_name}")
    refresh_decompiler_ctext(ea)


@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"],
):
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    tif = get_type_by_name(new_type)
    if not tif:
        raise IDAError("Parsed declaration is not a variable type")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
        raise IDAError("Failed to apply type")


def patch_address_assemble(
    ea: int,
    assemble: str,
) -> int:
    """Patch Address Assemble"""
    (check_assemble, bytes_to_patch) = idautils.Assemble(ea, assemble)
    if check_assemble == False:
        raise IDAError(f"Failed to assemble instruction: {assemble}")
    try:
        ida_bytes.patch_bytes(ea, bytes_to_patch)
    except:
        raise IDAError(f"Failed to patch bytes at address {hex(ea)}")

    return len(bytes_to_patch)


@idawrite
def patch_address_assembles(
    address: Annotated[str, "Starting Address to apply patch"],
    instructions: Annotated[str, "Assembly instructions separated by ';'"],
) -> str:
    ea = parse_address(address)
    assembles = instructions.split(";")
    for assemble in assembles:
        assemble = assemble.strip()
        try:
            patch_bytes_len = patch_address_assemble(ea, assemble)
        except IDAError as e:
            raise IDAError(f"Failed to patch bytes at address {hex(ea)}: {e}")
        ea += patch_bytes_len
    return f"Patched {len(assembles)} instructions"


@idaread
def get_global_variable_value_by_name(
    variable_name: Annotated[str, "Name of the global variable"],
) -> str:
    """
    Read a global variable's value (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    if ea == idaapi.BADADDR:
        raise IDAError(f"Global variable {variable_name} not found")

    return get_global_variable_value_internal(ea)


@idaread
def get_global_variable_value_at_address(
    address: Annotated[str, "Address of the global variable"],
) -> str:
    """
    Read a global variable's value by its address (if known at compile-time)

    Prefer this function over the `data_read_*` functions.
    """
    ea = parse_address(address)
    return get_global_variable_value_internal(ea)


def get_global_variable_value_internal(ea: int) -> str:
    # Get the type information for the variable
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        # No type info, maybe we can figure out its size by its name
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        # Determine the size of the variable
        size = tif.get_size()

    # Read the value based on the size
    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        # For other sizes, return the raw bytes
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@idawrite
def rename_function(
    function_address: Annotated[str, "Address of the function to rename"],
    new_name: Annotated[str, "New name for the function (empty for a default name)"],
):
    """Rename a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not idaapi.set_name(func.start_ea, new_name):
        raise IDAError(f"Failed to rename function {hex(func.start_ea)} to {new_name}")
    refresh_decompiler_ctext(func.start_ea)


@idawrite
def set_function_prototype(
    function_address: Annotated[str, "Address of the function"],
    prototype: Annotated[str, "New function prototype"],
):
    """Set a function's prototype"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    try:
        tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
        if not tif.is_func():
            raise IDAError("Parsed declaration is not a function type")
        if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
            raise IDAError("Failed to apply type")
        refresh_decompiler_ctext(func.start_ea)
    except Exception:
        raise IDAError(f"Failed to parse prototype string: {prototype}")


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvinf):
        for lvar_saved in lvinf.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False


# NOTE: This is extremely hacky, but necessary to get errors out of IDA
def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    if sys.platform == "win32":
        import ctypes

        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages: list[str] = []

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        # NOTE: The approach above could also work on other platforms, but it's
        # not been tested and there are differences in the vararg ABIs.
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages


@idawrite
def declare_c_type(
    c_declaration: Annotated[
        str,
        "C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };",
    ],
):
    """Create or update a local type from a C declaration"""
    # PT_SIL: Suppress warning dialogs (although it seems unnecessary here)
    # PT_EMPTY: Allow empty types (also unnecessary?)
    # PT_TYP: Print back status messages with struct tags
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
    errors, messages = parse_decls_ctypes(c_declaration, flags)

    pretty_messages = "\n".join(messages)
    if errors > 0:
        raise IDAError(
            f"Failed to parse type:\n{c_declaration}\n\nErrors:\n{pretty_messages}"
        )
    return f"success\n\nInfo:\n{pretty_messages}"


@idawrite
def set_local_variable_type(
    function_address: Annotated[
        str, "Address of the decompiled function containing the variable"
    ],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"],
):
    """Set a local variable's type"""
    try:
        # Some versions of IDA don't support this constructor
        new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    except Exception:
        try:
            new_tif = ida_typeinf.tinfo_t()
            # parse_decl requires semicolon for the type
            ida_typeinf.parse_decl(new_tif, None, new_type + ";", ida_typeinf.PT_SIL)  # type: ignore (IDA SDK type hints are incorrect)
        except Exception:
            raise IDAError(f"Failed to parse type: {new_type}")
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name):
        raise IDAError(f"Failed to find local variable: {variable_name}")
    modifier = my_modifier_t(variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func.start_ea, modifier):
        raise IDAError(f"Failed to modify local variable: {variable_name}")
    refresh_decompiler_ctext(func.start_ea)


@idaread
def get_stack_frame_variables(
    function_address: Annotated[
        str,
        "Address of the disassembled function to retrieve the stack frame variables",
    ],
) -> list[StackFrameVariable]:
    """Retrieve the stack frame variables for a given function"""
    return get_stack_frame_variables_internal(parse_address(function_address), True)


def get_stack_frame_variables_internal(
    function_address: int, raise_error: bool
) -> list[StackFrameVariable]:
    # TODO: IDA 8.3 does not support tif.get_type_by_tid
    if ida_major < 9:
        return []

    func = idaapi.get_func(function_address)
    if not func:
        if raise_error:
            raise IDAError(f"No function found at address {function_address}")
        return []

    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    members: list[StackFrameVariable] = []
    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    for udm in udt:
        if not udm.is_gap():
            name = udm.name
            offset = udm.offset // 8
            size = udm.size // 8
            type = str(udm.type)
            members.append(
                StackFrameVariable(
                    name=name, offset=hex(offset), size=hex(size), type=type
                )
            )
    return members


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]


@idaread
def get_defined_structures() -> list[StructureDefinition]:
    """Returns a list of all defined structures"""

    rv = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            udt = ida_typeinf.udt_type_data_t()
            members = []
            if tif.get_udt_details(udt):
                members = [
                    StructureMember(
                        name=x.name,
                        offset=hex(x.offset // 8),
                        size=hex(x.size // 8),
                        type=str(x.type),
                    )
                    for _, x in enumerate(udt)
                ]

            rv += [
                StructureDefinition(
                    name=tif.get_type_name(),  # type: ignore (IDA SDK type hints are incorrect)
                    size=hex(tif.get_size()),
                    members=members,
                )
            ]

    return rv


@idaread
def analyze_struct_detailed(
    name: Annotated[str, "Name of the structure to analyze"],
) -> dict:
    """Detailed analysis of a structure with all fields"""
    # Get tinfo object
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Structure '{name}' not found!")

    result = {
        "name": name,
        "type": str(tif._print()),
        "size": tif.get_size(),
        "is_udt": tif.is_udt(),
    }

    if not tif.is_udt():
        result["error"] = "This is not a user-defined type!"
        return result

    # Get UDT (User Defined Type) details
    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        result["error"] = "Failed to get structure details!"
        return result

    result["member_count"] = udt_data.size()
    result["is_union"] = udt_data.is_union
    result["udt_type"] = "Union" if udt_data.is_union else "Struct"

    # Output information about each field
    members = []
    for i, member in enumerate(udt_data):
        offset = member.begin() // 8  # Convert bits to bytes
        size = member.size // 8 if member.size > 0 else member.type.get_size()
        member_type = member.type._print()
        member_name = member.name

        member_info = {
            "index": i,
            "offset": f"0x{offset:08X}",
            "size": size,
            "type": member_type,
            "name": member_name,
            "is_nested_udt": member.type.is_udt(),
        }

        # If this is a nested structure, show additional information
        if member.type.is_udt():
            member_info["nested_size"] = member.type.get_size()

        members.append(member_info)

    result["members"] = members
    result["total_size"] = tif.get_size()

    return result


@idaread
def get_struct_at_address(
    address: Annotated[str, "Address to analyze structure at"],
    struct_name: Annotated[str, "Name of the structure"],
) -> dict:
    """Get structure field values at a specific address"""
    addr = parse_address(address)

    # Get structure tinfo
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        raise IDAError(f"Structure '{struct_name}' not found!")

    # Get structure details
    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        raise IDAError("Failed to get structure details!")

    result = {"struct_name": struct_name, "address": f"0x{addr:X}", "members": []}

    for member in udt_data:
        offset = member.begin() // 8
        member_addr = addr + offset
        member_type = member.type._print()
        member_name = member.name
        member_size = member.type.get_size()

        # Try to get value based on size
        try:
            if member.type.is_ptr():
                # Pointer
                is_64bit = (
                    ida_ida.inf_is_64bit()
                    if ida_major >= 9
                    else idaapi.get_inf_structure().is_64bit()
                )
                if is_64bit:
                    value = idaapi.get_qword(member_addr)
                    value_str = f"0x{value:016X}"
                else:
                    value = idaapi.get_dword(member_addr)
                    value_str = f"0x{value:08X}"
            elif member_size == 1:
                value = idaapi.get_byte(member_addr)
                value_str = f"0x{value:02X} ({value})"
            elif member_size == 2:
                value = idaapi.get_word(member_addr)
                value_str = f"0x{value:04X} ({value})"
            elif member_size == 4:
                value = idaapi.get_dword(member_addr)
                value_str = f"0x{value:08X} ({value})"
            elif member_size == 8:
                value = idaapi.get_qword(member_addr)
                value_str = f"0x{value:016X} ({value})"
            else:
                # For large structures, read first few bytes
                bytes_data = []
                for i in range(min(member_size, 16)):
                    try:
                        byte_val = idaapi.get_byte(member_addr + i)
                        bytes_data.append(f"{byte_val:02X}")
                    except:
                        break
                value_str = (
                    f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                )
        except:
            value_str = "<failed to read>"

        member_info = {
            "offset": f"0x{offset:08X}",
            "type": member_type,
            "name": member_name,
            "value": value_str,
        }

        result["members"].append(member_info)

    return result


@idaread
def get_struct_info_simple(name: Annotated[str, "Name of the structure"]) -> dict:
    """Simple function to get basic structure information"""
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Structure '{name}' not found!")

    info = {
        "name": name,
        "type": tif._print(),
        "size": tif.get_size(),
        "is_udt": tif.is_udt(),
    }

    if tif.is_udt():
        udt_data = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt_data):
            info["member_count"] = udt_data.size()
            info["is_union"] = udt_data.is_union

            members = []
            for member in udt_data:
                members.append(
                    {
                        "name": member.name,
                        "type": member.type._print(),
                        "offset": member.begin() // 8,
                        "size": member.type.get_size(),
                    }
                )
            info["members"] = members

    return info


@idaread
def search_structures(
    filter: Annotated[
        str, "Filter pattern to search for structures (case-insensitive)"
    ],
) -> list[dict]:
    """Search for structures by name pattern"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()  # type: ignore (IDA SDK type hints are incorrect)
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    member_count = 0
                    if tif.get_udt_details(udt_data):
                        member_count = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "member_count": member_count,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


@idawrite
def rename_stack_frame_variable(
    function_address: Annotated[
        str, "Address of the disassembled function to set the stack frame variables"
    ],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"],
):
    """Change the name of a stack variable for an IDA function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned.")

    idx, udm = frame_tif.get_udm(old_name)  # type: ignore (IDA SDK type hints are incorrect)
    if not udm:
        raise IDAError(f"{old_name} not found.")

    tid = frame_tif.get_udm_tid(idx)
    if ida_frame.is_special_frame_member(tid):
        raise IDAError(
            f"{old_name} is a special frame member. Will not change the name."
        )

    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8
    if ida_frame.is_funcarg_off(func, offset):
        raise IDAError(f"{old_name} is an argument member. Will not change the name.")

    sval = ida_frame.soff_to_fpoff(func, offset)
    if not ida_frame.define_stkvar(func, new_name, sval, udm.type):
        raise IDAError("failed to rename stack frame variable")


@idawrite
def create_stack_frame_variable(
    function_address: Annotated[
        str, "Address of the disassembled function to set the stack frame variables"
    ],
    offset: Annotated[str, "Offset of the stack frame variable"],
    variable_name: Annotated[str, "Name of the stack variable"],
    type_name: Annotated[str, "Type of the stack variable"],
):
    """For a given function, create a stack variable at an offset and with a specific type"""

    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    ea = parse_address(offset)

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned.")

    tif = get_type_by_name(type_name)
    if not ida_frame.define_stkvar(func, variable_name, ea, tif):
        raise IDAError("failed to define stack frame variable")


@idawrite
def set_stack_frame_variable_type(
    function_address: Annotated[
        str, "Address of the disassembled function to set the stack frame variables"
    ],
    variable_name: Annotated[str, "Name of the stack variable"],
    type_name: Annotated[str, "Type of the stack variable"],
):
    """For a given disassembled function, set the type of a stack variable"""

    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned.")

    idx, udm = frame_tif.get_udm(variable_name)  # type: ignore (IDA SDK type hints are incorrect)
    if not udm:
        raise IDAError(f"{variable_name} not found.")

    tid = frame_tif.get_udm_tid(idx)
    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8

    tif = get_type_by_name(type_name)
    if not ida_frame.set_frame_member_type(func, offset, tif):
        raise IDAError("failed to set stack frame variable type")


@idawrite
def delete_stack_frame_variable(
    function_address: Annotated[
        str, "Address of the function to set the stack frame variables"
    ],
    variable_name: Annotated[str, "Name of the stack variable"],
):
    """Delete the named stack variable for a given function"""

    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")

    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned.")

    idx, udm = frame_tif.get_udm(variable_name)  # type: ignore (IDA SDK type hints are incorrect)
    if not udm:
        raise IDAError(f"{variable_name} not found.")

    tid = frame_tif.get_udm_tid(idx)
    if ida_frame.is_special_frame_member(tid):
        raise IDAError(f"{variable_name} is a special frame member. Will not delete.")

    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8
    size = udm.size // 8
    if ida_frame.is_funcarg_off(func, offset):
        raise IDAError(f"{variable_name} is an argument member. Will not delete.")

    if not ida_frame.delete_frame_members(func, offset, offset + size):
        raise IDAError("failed to delete stack frame variable")


@idaread
def read_memory_bytes(
    memory_address: Annotated[str, "Address of the memory value to be read"],
    size: Annotated[int, "size of memory to read"],
) -> str:
    """
    Read bytes at a given address.

    Only use this function if `get_global_variable_at` and `get_global_variable_by_name`
    both failed.
    """
    return " ".join(
        f"{x:#02x}" for x in ida_bytes.get_bytes(parse_address(memory_address), size)
    )


@idaread
def data_read_byte(
    address: Annotated[str, "Address to get 1 byte value from"],
) -> int:
    """
    Read the 1 byte value at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    return ida_bytes.get_wide_byte(ea)


@idaread
def data_read_word(
    address: Annotated[str, "Address to get 2 bytes value from"],
) -> int:
    """
    Read the 2 byte value at the specified address as a WORD.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    return ida_bytes.get_wide_word(ea)


@idaread
def data_read_dword(
    address: Annotated[str, "Address to get 4 bytes value from"],
) -> int:
    """
    Read the 4 byte value at the specified address as a DWORD.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    return ida_bytes.get_wide_dword(ea)


@idaread
def data_read_qword(
    address: Annotated[str, "Address to get 8 bytes value from"],
) -> int:
    """
    Read the 8 byte value at the specified address as a QWORD.

    Only use this function if `get_global_variable_at` failed.
    """
    ea = parse_address(address)
    return ida_bytes.get_qword(ea)


@idaread
def data_read_string(address: Annotated[str, "Address to get string from"]) -> str:
    """
    Read the string at the specified address.

    Only use this function if `get_global_variable_at` failed.
    """
    try:
        return idaapi.get_strlit_contents(parse_address(address), -1, 0).decode("utf-8")
    except Exception as e:
        return "Error:" + str(e)


def open_database(
    db_path: str,
    *,
    auto_analysis: bool = True,
    new_database: bool = False,
    save_on_close: bool = False,
) -> Database:
    """
    Open an IDA database and return the handle.

    - auto_analysis: whether to run auto-analysis when opening
    - new_database : whether to force creating a new .idb/.i64
    - save_on_close: default save behavior if db.close() is called without a save argument
    """
    ida_opts = IdaCommandOptions(
        auto_analysis=auto_analysis,
        new_database=new_database,
    )

    db = Database.open(
        path=db_path,
        args=ida_opts,
        save_on_close=save_on_close,
    )
    # If opening fails a DatabaseError is raised; caller may catch as needed.  [oai_citation:3‡ida-domain-llms-full.txt](sediment://file_000000005d2c722fb252b8f677a8064d)
    return db


def close_database(
    db: Optional[Database],
    *,
    save: Optional[bool] = None,
) -> None:
    """
    Close an open IDA database.

    - save=None : use the save_on_close strategy specified at open()
    - save=True : force saving analysis results
    - save=False : discard modifications
    """
    if db is None:
        return

    # Defensive: it may already have been closed
    if hasattr(db, "is_open") and not db.is_open():
        return

    # Database.close(save) follows documented save/discard logic  [oai_citation:4‡ida-domain-llms-full.txt](sediment://file_000000005d2c722fb252b8f677a8064d)
    db.close(save=save)
