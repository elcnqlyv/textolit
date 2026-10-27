from textolit.modules.unpack import parse_signatures

SAMPLE = """
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes
4096          0x1000          Squashfs filesystem, little endian, version 4.0, size: 403 bytes
65536         0x10000         JFFS2 filesystem, little endian
"""


def test_parse_signatures() -> None:
    sigs = parse_signatures(SAMPLE)
    assert [s["offset"] for s in sigs] == [0, 4096, 65536]
    assert [s["filesystem"] for s in sigs] == [None, "squashfs", "jffs2"]
