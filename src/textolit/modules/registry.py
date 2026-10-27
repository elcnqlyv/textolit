"""Module lookup. Built per call so there is no shared mutable registry."""

from __future__ import annotations

from textolit.modules.base import Module
from textolit.modules.binintel import BinIntel
from textolit.modules.crypto import Crypto
from textolit.modules.entropy import Entropy
from textolit.modules.fswalk import FsWalk
from textolit.modules.ingest import Ingest
from textolit.modules.llm import Llm
from textolit.modules.missedfindings import MissedFindings
from textolit.modules.netmap import NetMap
from textolit.modules.unpack import Unpack
from textolit.modules.websurface import WebSurface


def builtin_modules() -> dict[str, Module]:
    mods: list[Module] = [
        Ingest(),
        Unpack(),
        Entropy(),
        FsWalk(),
        BinIntel(),
        NetMap(),
        MissedFindings(),
        Crypto(),
        WebSurface(),
        Llm(),
    ]
    return {m.name: m for m in mods}
