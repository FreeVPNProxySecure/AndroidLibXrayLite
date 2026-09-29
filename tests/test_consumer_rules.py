from __future__ import annotations

import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from scripts.consumer_rules import HEADER, RULES_ENTRY, generate, replace_rules
from scripts.validate_build_contract import ContractError


STATIC, NATIVE, INTERFACE, ABSTRACT = 0x0008, 0x0100, 0x0200, 0x0400


def class_file(name, interfaces=(), fields=(), methods=(), access=0x0001):
    """A minimal class file with the constant pool, hierarchy and members."""
    pool, slots, next_index = [], {}, [1]

    def add(key, entry, width=1):
        if key not in slots:
            pool.append(entry)
            slots[key] = next_index[0]
            next_index[0] += width
        return slots[key]

    def utf8(value):
        data = value.encode()
        return add(("u", value), b"\x01" + struct.pack(">H", len(data)) + data)

    def klass(value):
        return add(("c", value), b"\x07" + struct.pack(">H", utf8(value)))

    this_ref, super_ref = klass(name), klass("java/lang/Object")
    interface_refs = [klass(item) for item in interfaces]
    add(("long",), b"\x05" + struct.pack(">q", 42), width=2)
    groups = [[(flags, utf8(n), utf8(d)) for flags, n, d in group] for group in (fields, methods)]
    output = struct.pack(">IHHH", 0xCAFEBABE, 0, 52, next_index[0]) + b"".join(pool)
    output += struct.pack(">HHHH", access, this_ref, super_ref, len(interface_refs))
    output += b"".join(struct.pack(">H", ref) for ref in interface_refs)
    for group in groups:
        output += struct.pack(">H", len(group))
        output += b"".join(struct.pack(">HHHH", flags, n, d, 0) for flags, n, d in group)
    return output + struct.pack(">H", 0)


def binding_classes():
    return {
        "go/Seq": class_file("go/Seq", methods=(
            (STATIC, "getRef", "(I)Lgo/Seq$Ref;"), (STATIC, "decRef", "(I)V"),
            (STATIC, "incRefnum", "(I)V"), (STATIC, "incRef", "(Ljava/lang/Object;)I"),
            (STATIC, "incGoObjectRef", "(Lgo/Seq$GoObject;)I"), (STATIC, "touch", "()V"),
            (STATIC | NATIVE, "init", "()V"), (STATIC | NATIVE, "destroyRef", "(I)V"),
        )),
        "go/Seq$Ref": class_file("go/Seq$Ref", fields=((0, "obj", "Ljava/lang/Object;"),)),
        "go/Seq$Proxy": class_file("go/Seq$Proxy", access=INTERFACE | ABSTRACT),
        "go/Universe": class_file("go/Universe", methods=((STATIC | NATIVE, "_init", "()V"),)),
        "go/Universe$proxyerror": class_file(
            "go/Universe$proxyerror", interfaces=("go/Seq$Proxy", "go/error"),
            methods=((0, "<init>", "(I)V"), (NATIVE, "error", "()Ljava/lang/String;")),
        ),
        "demo/Demo": class_file("demo/Demo", methods=((STATIC | NATIVE, "_init", "()V"),)),
        "demo/Demo$proxyCallback": class_file(
            "demo/Demo$proxyCallback", interfaces=("go/Seq$Proxy", "demo/Callback"),
            methods=((0, "<init>", "(I)V"), (NATIVE, "protect", "(J)Z")),
        ),
        "demo/Callback": class_file(
            "demo/Callback", access=INTERFACE | ABSTRACT, methods=((ABSTRACT, "protect", "(J)Z"),)
        ),
        "demo/Point": class_file(
            "demo/Point", interfaces=("go/Seq$Proxy",),
            methods=((0, "<init>", "(I)V"), (NATIVE, "runLoop", "(Z)V"), (0, "hashCode", "()I")),
        ),
    }


def jar(classes):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in sorted(classes):
            archive.writestr(name + ".class", classes[name])
    return buffer.getvalue()


EXPECTED = HEADER + """\
-keep,includedescriptorclasses class go.Seq {
    void decRef(int);
    go.Seq$Ref getRef(int);
    int incGoObjectRef(go.Seq$GoObject);
    int incRef(java.lang.Object);
    void incRefnum(int);
}
-keep class go.Seq$Ref {
    java.lang.Object obj;
}
-keep,includedescriptorclasses interface demo.Callback {
    <methods>;
}
-keep class demo.Demo$proxyCallback {
    <init>(int);
}
-keep class demo.Point {
    <init>(int);
}
-keep class go.Universe$proxyerror {
    <init>(int);
}
-keepclasseswithmembernames,includedescriptorclasses class demo.Demo {
    native <methods>;
}
-keepclasseswithmembernames,includedescriptorclasses class demo.Demo$proxyCallback {
    native <methods>;
}
-keepclasseswithmembernames,includedescriptorclasses class demo.Point {
    native <methods>;
}
-keepclasseswithmembernames,includedescriptorclasses class go.Seq {
    native <methods>;
}
-keepclasseswithmembernames,includedescriptorclasses class go.Universe {
    native <methods>;
}
-keepclasseswithmembernames,includedescriptorclasses class go.Universe$proxyerror {
    native <methods>;
}
"""


class _Unseekable(io.RawIOBase):
    """Forces zipfile to stream entries with data descriptors, like Go's writer."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, payload) -> int:
        self.data += payload
        return len(payload)


def gomobile_style_aar(classes_jar: bytes) -> bytes:
    stream = _Unseekable()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="go.demo.gojni"/>')
        archive.writestr(RULES_ENTRY, "-keep class go.** { *; }\n-keep class demo.** { *; }\n")
        archive.writestr("classes.jar", classes_jar)
        archive.writestr("jni/arm64-v8a/libgojni.so", b"\x7fELF" + bytes(range(256)) * 64)
        archive.writestr(zipfile.ZipInfo("res/"), b"")
    return bytes(stream.data)


class ConsumerRulesTest(unittest.TestCase):
    def test_generates_exact_rules_for_every_name_based_lookup(self) -> None:
        rules = generate(jar(binding_classes()))
        self.assertEqual(EXPECTED, rules)
        self.assertNotIn("*", "".join(line for line in rules.splitlines() if line.startswith("-")))

    def test_generator_invariants_fail_closed(self) -> None:
        for name in ("demo/Demo$proxyCallback", "go/Seq$Ref"):
            classes = binding_classes()
            del classes[name]
            with self.subTest(name), self.assertRaises(ContractError):
                generate(jar(classes))
        classes = binding_classes()
        classes["demo/Point"] = class_file("demo/Point", interfaces=("go/Seq$Proxy",))
        with self.assertRaisesRegex(ContractError, "refnum constructor"):
            generate(jar(classes))

    def test_replaces_rules_and_copies_other_entries_byte_for_byte(self) -> None:
        original = gomobile_style_aar(jar(binding_classes()))
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libv2ray.aar"
            artifact.write_bytes(original)
            self.assertEqual(EXPECTED, replace_rules(artifact))
            rewritten = artifact.read_bytes()
            self.assertEqual([], [p.name for p in Path(directory).iterdir() if p.name != artifact.name])
        before, after = zipfile.ZipFile(io.BytesIO(original)), zipfile.ZipFile(io.BytesIO(rewritten))
        self.assertIsNone(after.testzip())
        self.assertEqual([i.filename for i in before.infolist()], [i.filename for i in after.infolist()])
        for old, new in zip(before.infolist(), after.infolist()):
            if old.filename == RULES_ENTRY:
                self.assertEqual(EXPECTED.encode(), after.read(new))
                self.assertEqual((zipfile.ZIP_STORED, (1980, 0, 0, 0, 0, 0)), (new.compress_type, new.date_time))
                continue
            self.assertTrue(old.flag_bits & 0x08 or old.is_dir())
            start, end = old.header_offset, old.header_offset + 30 + len(old.filename) + old.compress_size
            moved = new.header_offset - old.header_offset
            self.assertEqual(original[start:end + 16], rewritten[start + moved:end + moved + 16])

    def test_rejects_an_aar_without_rules_entry(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("classes.jar", jar(binding_classes()))
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "libv2ray.aar"
            artifact.write_bytes(buffer.getvalue())
            with self.assertRaises(ContractError):
                replace_rules(artifact)


if __name__ == "__main__":
    unittest.main()
