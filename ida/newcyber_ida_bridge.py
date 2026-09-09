# NewCyber IDA Bridge
# Offline exporter for IDA Pro / IDAPython.
# It never connects to the network and never executes target code.

import datetime
import json
import os

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_segment
import idautils
import idc

SCHEMA = "newcyber.ida-snapshot.v1"
EXPORTER_VERSION = "0.1"
MAX_HEADS = 250000
MAX_FUNCTIONS = 50000
MAX_XREFS_PER_ITEM = 32
MAX_DATA_PREVIEW = 4096
MAX_TOTAL_PREVIEW_BYTES = 16 * 1024 * 1024
MAX_LISTING_CHARS = 1800 * 1024


def _hex(ea):
    return "0x%x" % int(ea)


def _safe_text(value):
    if value is None:
        return ""
    return str(value)


def _strip_tags(text):
    try:
        return ida_lines.tag_remove(text or "")
    except Exception:
        return text or ""


def _processor_name():
    try:
        return ida_ida.inf_get_procname()
    except Exception:
        try:
            return idaapi.get_inf_structure().procname
        except Exception:
            return "unknown"


def _bitness():
    try:
        if ida_ida.inf_is_64bit():
            return 64
        if ida_ida.inf_is_32bit_exactly():
            return 32
        return 16
    except Exception:
        try:
            inf = idaapi.get_inf_structure()
            if inf.is_64bit():
                return 64
            if inf.is_32bit():
                return 32
            return 16
        except Exception:
            return 0


def _image_base():
    try:
        return int(ida_nalt.get_imagebase())
    except Exception:
        try:
            return int(idaapi.get_imagebase())
        except Exception:
            return 0


def _kernel_version():
    try:
        return _safe_text(idaapi.get_kernel_version())
    except Exception:
        return "unknown"


def _input_md5():
    try:
        value = ida_nalt.retrieve_input_file_md5()
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).hex()
        return _safe_text(value)
    except Exception:
        return ""


def _segment_name(seg):
    try:
        return ida_segment.get_segm_name(seg)
    except Exception:
        return "seg_%x" % int(seg.start_ea)


def _segment_class(seg):
    try:
        return ida_segment.get_segm_class(seg)
    except Exception:
        return ""


def _segment_permissions(seg):
    perm = int(getattr(seg, "perm", 0))
    read = bool(perm & int(getattr(ida_segment, "SEGPERM_READ", 4)))
    write = bool(perm & int(getattr(ida_segment, "SEGPERM_WRITE", 2)))
    execute = bool(perm & int(getattr(ida_segment, "SEGPERM_EXEC", 1)))
    return {"read": read, "write": write, "execute": execute, "raw": perm}


def _xref_rows(iterator):
    rows = []
    for xref in iterator:
        rows.append({
            "from": _hex(xref.frm),
            "to": _hex(xref.to),
            "type": int(xref.type),
            "isCode": bool(xref.iscode),
        })
        if len(rows) >= MAX_XREFS_PER_ITEM:
            break
    return rows


def _bytes_hex(ea, size, remaining_budget):
    if size <= 0 or remaining_budget <= 0:
        return "", 0, False
    wanted = min(int(size), MAX_DATA_PREVIEW, int(remaining_budget))
    try:
        raw = ida_bytes.get_bytes(ea, wanted)
    except Exception:
        raw = None
    if not raw:
        return "", 0, False
    data = bytes(raw)
    return data.hex(" "), len(data), int(size) > len(data)


def _function_for_ea(ea):
    try:
        fn = ida_funcs.get_func(ea)
        if not fn:
            return None
        name = ida_funcs.get_func_name(fn.start_ea) or idc.get_func_name(fn.start_ea)
        return {
            "name": _safe_text(name),
            "start": _hex(fn.start_ea),
            "end": _hex(fn.end_ea),
        }
    except Exception:
        return None


def _item_kind(ea):
    flags = ida_bytes.get_full_flags(ea)
    if ida_bytes.is_code(flags):
        return "code"
    if ida_bytes.is_data(flags):
        return "data"
    return "unknown"


def _disasm(ea):
    try:
        return _strip_tags(idc.generate_disasm_line(ea, 0) or "")
    except Exception:
        return ""


def _operands(ea):
    out = []
    for index in range(6):
        try:
            value = idc.print_operand(ea, index)
        except Exception:
            value = ""
        if not value:
            break
        out.append(_strip_tags(value))
    return out


def _comments(ea):
    values = []
    for repeatable in (0, 1):
        try:
            value = idc.get_cmt(ea, repeatable)
        except Exception:
            value = None
        if value:
            values.append(_safe_text(value))
    return values


def _collect_segments():
    rows = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if not seg:
            continue
        rows.append({
            "name": _segment_name(seg),
            "class": _segment_class(seg),
            "start": _hex(seg.start_ea),
            "end": _hex(seg.end_ea),
            "size": int(seg.end_ea - seg.start_ea),
            "permissions": _segment_permissions(seg),
        })
    return rows


def _collect_functions():
    rows = []
    truncated = False
    for index, start in enumerate(idautils.Functions()):
        if index >= MAX_FUNCTIONS:
            truncated = True
            break
        fn = ida_funcs.get_func(start)
        if not fn:
            continue
        rows.append({
            "name": _safe_text(ida_funcs.get_func_name(start) or idc.get_func_name(start)),
            "start": _hex(fn.start_ea),
            "end": _hex(fn.end_ea),
            "size": int(fn.end_ea - fn.start_ea),
        })
    return rows, truncated


def _collect_items(segments):
    items = []
    listing = []
    listing_chars = 0
    preview_budget = MAX_TOTAL_PREVIEW_BYTES
    heads_truncated = False
    listing_truncated = False
    function_starts = set()

    for segment in segments:
        start = int(segment["start"], 16)
        end = int(segment["end"], 16)
        seg_name = segment["name"]
        for ea in idautils.Heads(start, end):
            if len(items) >= MAX_HEADS:
                heads_truncated = True
                break
            kind = _item_kind(ea)
            size = max(1, int(idc.get_item_size(ea) or 1))
            name = _safe_text(idc.get_name(ea, idc.GN_VISIBLE) or "")
            func = _function_for_ea(ea)
            disasm = _disasm(ea)
            bytes_hex, preview_size, preview_truncated = _bytes_hex(ea, size, preview_budget)
            preview_budget -= preview_size

            if func and int(func["start"], 16) == int(ea) and int(ea) not in function_starts:
                function_starts.add(int(ea))
                proc_line = "%s:%016X %s proc near" % (seg_name, int(ea), func["name"] or ("sub_%X" % int(ea)))
                if listing_chars + len(proc_line) + 1 <= MAX_LISTING_CHARS:
                    listing.append(proc_line)
                    listing_chars += len(proc_line) + 1
                else:
                    listing_truncated = True

            line = "%s:%016X %s" % (seg_name, int(ea), disasm)
            if not listing_truncated:
                if listing_chars + len(line) + 1 <= MAX_LISTING_CHARS:
                    listing.append(line)
                    listing_chars += len(line) + 1
                else:
                    listing_truncated = True

            item = {
                "address": _hex(ea),
                "segment": seg_name,
                "kind": kind,
                "name": name,
                "size": size,
                "disasm": disasm,
                "bytesHex": bytes_hex,
                "bytesPreviewSize": preview_size,
                "bytesTruncated": preview_truncated,
                "xrefsFrom": _xref_rows(idautils.XrefsFrom(ea, 0)),
                "xrefsTo": _xref_rows(idautils.XrefsTo(ea, 0)),
                "comments": _comments(ea),
            }
            if kind == "code":
                item["mnemonic"] = _safe_text(idc.print_insn_mnem(ea) or "")
                item["operands"] = _operands(ea)
                if func:
                    item["function"] = func["name"]
                    item["functionStart"] = func["start"]
            items.append(item)
        if heads_truncated:
            break

    return items, listing, {
        "headsTruncated": heads_truncated,
        "listingTruncated": listing_truncated,
        "previewBytesUsed": MAX_TOTAL_PREVIEW_BYTES - preview_budget,
        "previewBudgetExhausted": preview_budget <= 0,
    }


def build_snapshot():
    segments = _collect_segments()
    functions, functions_truncated = _collect_functions()
    items, listing, limits = _collect_items(segments)
    limits["functionsTruncated"] = functions_truncated

    try:
        input_path = ida_nalt.get_input_file_path() or ""
    except Exception:
        input_path = ""

    return {
        "schema": SCHEMA,
        "exporterVersion": EXPORTER_VERSION,
        "exportedAt": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "ida": {
            "version": _kernel_version(),
            "processor": _processor_name(),
            "bitness": _bitness(),
            "imageBase": _hex(_image_base()),
            "inputFile": os.path.basename(input_path) if input_path else "",
            "inputPath": input_path,
            "inputMd5": _input_md5(),
        },
        "limits": {
            "maxHeads": MAX_HEADS,
            "maxFunctions": MAX_FUNCTIONS,
            "maxListingChars": MAX_LISTING_CHARS,
            "maxTotalPreviewBytes": MAX_TOTAL_PREVIEW_BYTES,
            **limits,
        },
        "segments": segments,
        "functions": functions,
        "items": items,
        "listing": listing,
    }


def export_snapshot(path=None):
    if path is None:
        input_name = "binary"
        try:
            input_name = os.path.basename(ida_nalt.get_input_file_path() or "binary")
        except Exception:
            pass
        default_name = "%s.newcyber-ida.json" % input_name
        path = ida_kernwin.ask_file(True, default_name, "Export NewCyber IDA Snapshot")
    if not path:
        ida_kernwin.msg("[NewCyber] export cancelled\n")
        return None

    snapshot = build_snapshot()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, ensure_ascii=False, separators=(",", ":"))
    ida_kernwin.msg(
        "[NewCyber] snapshot exported: %s | %d functions | %d items | %d listing lines%s\n"
        % (
            path,
            len(snapshot["functions"]),
            len(snapshot["items"]),
            len(snapshot["listing"]),
            " | TRUNCATED" if any(
                snapshot["limits"].get(key)
                for key in ("headsTruncated", "listingTruncated", "functionsTruncated", "previewBudgetExhausted")
            ) else "",
        )
    )
    return path


class NewCyberIdaBridgePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Export deterministic IDA facts for NewCyber Binary Data Graph"
    help = "Exports segments, functions, names, bytes, xrefs and disassembly without executing the target."
    wanted_name = "NewCyber: Export Snapshot"
    wanted_hotkey = "Ctrl-Alt-N"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            export_snapshot()
        except Exception as exc:
            ida_kernwin.warning("NewCyber export failed: %s" % exc)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return NewCyberIdaBridgePlugin()


if __name__ == "__main__":
    export_snapshot()
