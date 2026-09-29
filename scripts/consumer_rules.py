#!/usr/bin/env python3
"""Exact consumer keep rules for the gomobile JNI contract of libv2ray.aar.

gomobile writes ``-keep class go.** { *; }`` and ``-keep class libv2ray.** { *; }``
into the AAR. Those rules keep every member of the binding and any class of the
consuming application under ``go.*``. The native code only needs the classes and
members it resolves by name (golang.org/x/mobile at the locked gomobile commit):

- ``bind/java/seq_android.c.support`` ``Java_go_Seq_init``: the static methods
  ``go.Seq.getRef``, ``decRef``, ``incRefnum``, ``incRef`` and ``incGoObjectRef``,
  the class ``go.Seq$Ref`` and its field ``obj``. A failed lookup is fatal.
- ``bind/genjava.go`` ``GenC`` (``<Package>._init`` of every bound package and of
  the universe package): ``FindClass`` of every class that proxies a Go object
  with ``GetMethodID("<init>", "(I)V")``, and ``FindClass`` of every generated
  interface with ``GetMethodID`` of each of its methods. Go calls Java
  implementations of these interfaces through those method IDs.
- Java calls into Go through statically registered native methods
  (``Java_<class>_<method>`` exports, locked in the Android API baseline).

Reverse bindings (``bind/genclasses.go``) add further lookups; a binding that
uses them is rejected. The build replaces the generated ``proguard.txt`` with
these rules and ``verify_aar`` requires them.
"""

from __future__ import annotations

import io
from pathlib import Path
import struct
import zipfile
import zlib

try:
    from .validate_build_contract import ContractError
except ImportError:
    from validate_build_contract import ContractError


RULES_ENTRY = "proguard.txt"
HEADER = (
    "# Generated from the gomobile JNI contract of this binding: native code\n"
    "# resolves these classes and members by name. Do not edit by hand.\n"
)
PROXY_INTERFACE = "go/Seq$Proxy"
SEQ_CLASS = "go/Seq"
SEQ_REF_CLASS = "go/Seq$Ref"
RUNTIME_PACKAGE = "go"
SEQ_STATIC_METHODS = (
    ("decRef", "(I)V"),
    ("getRef", "(I)Lgo/Seq$Ref;"),
    ("incGoObjectRef", "(Lgo/Seq$GoObject;)I"),
    ("incRef", "(Ljava/lang/Object;)I"),
    ("incRefnum", "(I)V"),
)
ACC_STATIC = 0x0008
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
_CONSTANT_SIZES = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def parse_class(payload: bytes) -> dict:
    """Name, access flags, interfaces and member signatures of one class file."""
    try:
        magic, _minor, _major, count = struct.unpack_from(">IHHH", payload, 0)
        if magic != 0xCAFEBABE:
            raise ContractError("not a class file")
        position = 10
        utf8: dict[int, str] = {}
        class_refs: dict[int, int] = {}
        index = 1
        while index < count:
            tag = payload[position]
            position += 1
            if tag == 1:
                (length,) = struct.unpack_from(">H", payload, position)
                utf8[index] = payload[position + 2:position + 2 + length].decode("utf-8", "surrogatepass")
                position += 2 + length
            elif tag in _CONSTANT_SIZES:
                if tag == 7:
                    (class_refs[index],) = struct.unpack_from(">H", payload, position)
                position += _CONSTANT_SIZES[tag]
                index += 1 if tag in (5, 6) else 0
            else:
                raise ContractError(f"unknown constant pool tag {tag}")
            index += 1
        access, this_ref, _super_ref, interface_count = struct.unpack_from(">HHHH", payload, position)
        position += 8
        interfaces = []
        for _ in range(interface_count):
            (ref,) = struct.unpack_from(">H", payload, position)
            interfaces.append(utf8[class_refs[ref]])
            position += 2
        groups = []
        for _ in range(2):
            (member_count,) = struct.unpack_from(">H", payload, position)
            position += 2
            members = []
            for _ in range(member_count):
                flags, name_ref, descriptor_ref, attributes = struct.unpack_from(">HHHH", payload, position)
                position += 8
                for _ in range(attributes):
                    (length,) = struct.unpack_from(">I", payload, position + 2)
                    position += 6 + length
                members.append((flags, utf8[name_ref], utf8[descriptor_ref]))
            groups.append(members)
    except (struct.error, IndexError, KeyError) as error:
        raise ContractError(f"malformed class file: {error}") from error
    name = utf8[class_refs[this_ref]]
    return {
        "name": name,
        "package": name.rsplit("/", 1)[0] if "/" in name else "",
        "access": access,
        "interfaces": interfaces,
        "fields": groups[0],
        "methods": groups[1],
    }


def read_classes(classes_jar: bytes) -> dict[str, dict]:
    classes = {}
    with zipfile.ZipFile(io.BytesIO(classes_jar)) as archive:
        for entry in archive.namelist():
            if entry.endswith(".class"):
                parsed = parse_class(archive.read(entry))
                if parsed["name"] + ".class" != entry:
                    raise ContractError(f"{entry} declares {parsed['name']}")
                classes[parsed["name"]] = parsed
    return classes


def _package_class(package: str) -> str:
    if package == RUNTIME_PACKAGE:
        return f"{RUNTIME_PACKAGE}/Universe"
    last = package.rsplit("/", 1)[-1]
    return f"{package}/{last[:1].upper()}{last[1:]}"


def _has(members: list, name: str, descriptor: str, required: int = 0) -> bool:
    return any(m[1] == name and m[2] == descriptor and m[0] & required == required for m in members)


def _java_type(descriptor: str) -> tuple[str, int]:
    dimensions = len(descriptor) - len(descriptor.lstrip("["))
    head = descriptor[dimensions]
    primitives = {"B": "byte", "C": "char", "D": "double", "F": "float", "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void"}
    if head == "L":
        end = descriptor.index(";", dimensions)
        return descriptor[dimensions + 1:end].replace("/", ".") + "[]" * dimensions, end + 1
    return primitives[head] + "[]" * dimensions, dimensions + 1


def _java_signature(name: str, descriptor: str) -> str:
    parameters, position = [], 1
    while descriptor[position] != ")":
        value, consumed = _java_type(descriptor[position:])
        parameters.append(value)
        position += consumed
    return f"{_java_type(descriptor[position + 1:])[0]} {name}({','.join(parameters)})"


def _rule(option: str, kind: str, name: str, members: list[str]) -> str:
    body = "".join(f"    {member};\n" for member in members)
    return f"{option} {kind} {name.replace('/', '.')} {{\n{body}}}\n"


def generate(classes_jar: bytes) -> str:
    """The keep rules for every class and member resolved by name."""
    classes = read_classes(classes_jar)
    seq, ref = classes.get(SEQ_CLASS), classes.get(SEQ_REF_CLASS)
    if seq is None or ref is None:
        raise ContractError("gomobile runtime go.Seq or go.Seq$Ref is missing")
    for name, descriptor in SEQ_STATIC_METHODS:
        if not _has(seq["methods"], name, descriptor, ACC_STATIC):
            raise ContractError(f"go.Seq lacks static {name}{descriptor}")
    if not _has(ref["fields"], "obj", "Ljava/lang/Object;"):
        raise ContractError("go.Seq$Ref lacks field obj")
    proxies = sorted(name for name, item in classes.items() if PROXY_INTERFACE in item["interfaces"])
    bound = {classes[name]["package"] for name in proxies} - {RUNTIME_PACKAGE}
    if not bound:
        raise ContractError("no bound package: no class implements go.Seq$Proxy outside go")
    lookups: dict[str, str] = {}
    for name in proxies:
        item = classes[name]
        if not _has(item["methods"], "<init>", "(I)V"):
            raise ContractError(f"proxy class lacks the refnum constructor: {name}")
        owner, _, proxied = name.rsplit("/", 1)[-1].partition("$proxy")
        if proxied:
            if f"{item['package']}/{owner}" != _package_class(item["package"]):
                raise ContractError(f"interface proxy outside its package class: {name}")
            interface = classes.get(f"{item['package']}/{proxied}")
            if item["package"] != RUNTIME_PACKAGE and (interface is None or not interface["access"] & ACC_INTERFACE):
                raise ContractError(f"interface proxy without its interface: {name}")
        lookups[name] = _rule("-keep", "class", name, ["<init>(int)"])
    for name, item in classes.items():
        if not item["access"] & ACC_INTERFACE or item["package"] not in bound:
            continue
        if _package_class(item["package"]) + "$proxy" + name.rsplit("/", 1)[-1] not in classes:
            raise ContractError(f"interface without its proxy class: {name}")
        methods = [m for m in item["methods"] if m[1] != "<clinit>"]
        if not methods or any(not m[0] & ACC_ABSTRACT or m[0] & ACC_STATIC for m in methods):
            raise ContractError(f"generated interface has unexpected methods: {name}")
        # Every declared method is resolved with GetMethodID: the generator
        # declares exactly the methods whose signatures it supports.
        lookups[name] = _rule("-keep,includedescriptorclasses", "interface", name, ["<methods>"])
    natives = []
    for name in sorted(classes):
        item = classes[name]
        names = [m[1] for m in item["methods"] if m[0] & ACC_NATIVE]
        if not names:
            continue
        if item["package"] != RUNTIME_PACKAGE and item["package"] not in bound:
            raise ContractError(f"native method outside the bound packages: {name}")
        if len(names) != len(set(names)):
            raise ContractError(f"overloaded native method needs long JNI names: {name}")
        natives.append(
            _rule("-keepclasseswithmembernames,includedescriptorclasses", "class", name, ["native <methods>"])
        )
    return (
        HEADER
        + _rule("-keep,includedescriptorclasses", "class", SEQ_CLASS, [_java_signature(*m) for m in SEQ_STATIC_METHODS])
        + _rule("-keep", "class", SEQ_REF_CLASS, ["java.lang.Object obj"])
        + "".join(lookups[name] for name in sorted(lookups))
        + "".join(natives)
    )


# --------------------------------------------------------------------------
# AAR rewrite


_LOCAL = b"PK\x03\x04"
_CENTRAL = b"PK\x01\x02"
_END = b"PK\x05\x06"
_DESCRIPTOR = b"PK\x07\x08"


def _local_entry(payload: bytes, info: zipfile.ZipInfo) -> bytes:
    """The local header, data and data descriptor of one entry, unchanged."""
    start = info.header_offset
    if payload[start:start + 4] != _LOCAL:
        raise ContractError(f"bad local header for {info.filename}")
    name_length, extra_length = struct.unpack_from("<HH", payload, start + 26)
    end = start + 30 + name_length + extra_length + info.compress_size
    if info.flag_bits & 0x08:
        end += 16 if payload[end:end + 4] == _DESCRIPTOR else 12
    return payload[start:end]


def replace_rules(artifact: Path) -> str:
    """Replace the gomobile rules of an AAR with the generated rules.

    Every other entry and its central directory record is copied byte for byte
    in the original order. The rules entry is stored uncompressed with the same
    fixed timestamp, so the result does not depend on the host zlib.
    """
    payload = artifact.read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        infos = archive.infolist()
        rules = generate(archive.read("classes.jar")).encode("utf-8")
    if sum(info.filename == RULES_ENTRY for info in infos) != 1:
        raise ContractError(f"AAR must contain exactly one {RULES_ENTRY}")
    end = payload.rfind(_END)
    if end < 0 or payload[end + 20:end + 22] != b"\x00\x00" or end + 22 != len(payload):
        raise ContractError("AAR has an archive comment or no end of central directory")
    entries, directory_size, directory_offset = struct.unpack_from("<HII", payload, end + 10)
    if entries != len(infos) or any(
        info.compress_size >= 0xFFFFFFFF or info.header_offset >= 0xFFFFFFFF for info in infos
    ):
        raise ContractError("ZIP64 AARs are not supported")
    records = []
    position = directory_offset
    for _ in range(entries):
        if payload[position:position + 4] != _CENTRAL:
            raise ContractError("bad central directory record")
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", payload, position + 28)
        size = 46 + name_length + extra_length + comment_length
        records.append(bytearray(payload[position:position + size]))
        position += size
    if position != directory_offset + directory_size:
        raise ContractError("central directory size mismatch")

    output = bytearray()
    directory = bytearray()
    for info, record in zip(infos, records):
        offset = len(output)
        if info.filename == RULES_ENTRY:
            name = info.filename.encode("utf-8")
            crc = zlib.crc32(rules)
            output += _LOCAL + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0, crc, len(rules), len(rules), len(name), 0)
            output += name + rules
            directory += _CENTRAL + struct.pack(
                "<HHHHHHIIIHHHHHII", 20, 20, 0, 0, 0, 0, crc, len(rules), len(rules), len(name), 0, 0, 0, 0, 0, offset
            ) + name
            continue
        output += _local_entry(payload, info)
        struct.pack_into("<I", record, 42, offset)
        directory += record
    rewritten_directory_offset = len(output)
    output += directory + _END + struct.pack(
        "<HHHHIIH", 0, 0, len(infos), len(infos), len(directory), rewritten_directory_offset, 0
    )
    temporary = artifact.with_name(f".{artifact.name}.rules")
    temporary.write_bytes(bytes(output))
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None or [i.filename for i in archive.infolist()] != [i.filename for i in infos]:
            temporary.unlink()
            raise ContractError("rewritten AAR failed verification")
        if archive.read(RULES_ENTRY) != rules:
            temporary.unlink()
            raise ContractError("rewritten AAR has unexpected rules")
    temporary.replace(artifact)
    return rules.decode("utf-8")
