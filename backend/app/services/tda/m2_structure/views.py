"""M2 bounded, attestable transformations over M1 ORIGINAL fields/keys.

M2 owns obfuscation views and records *original enclosing source spans*.
An attested conversion proves how text was derived, not that an instruction
inside it is malicious, that it was executed, or that derived character offsets
map one-to-one to ORIGINAL text. No model, network or permissions.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from html import unescape
import base64
import re
import unicodedata
from typing import Literal

from app.services.tda.m1_sources.capture import AnalysisContext
from app.services.tda.m1_sources.contracts import Evidence

MAX_SOURCE_CHARS = 16_000
MAX_DERIVED_VIEWS = 48
MAX_AGGREGATE_DERIVED_CHARS = 64_000
MAX_BASE64_TOKEN = 4096
MAX_DERIVED_PER_ORIGIN = 4
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,4096}={0,2}(?![A-Za-z0-9+/=])")
HTML_ENTITY = re.compile(r"(?:&(?:#[xX][0-9a-fA-F]+|#[0-9]+|[A-Za-z][A-Za-z0-9]+);)")
UNICODE_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
TAG_BLOCK = re.compile("[\U000e0020-\U000e007e]{5,}\U000e007f?")
LETTER_SPACING = re.compile(r"\b(?:[A-Za-z][ \t]){4,14}[A-Za-z]\b")
# Narrow, published substitutions; never fold a wholly Cyrillic/Greek word.
CYRILLIC_TO_LATIN = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u043a": "k",
    "\u043c": "m", "\u0442": "t", "\u0432": "b", "\u043d": "h",
    "\u0456": "i", "\u0406": "I", "\u0410": "A", "\u0415": "E",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0425": "X",
})


def _script_latin(ch: str) -> bool:
    return "LATIN" in unicodedata.name(ch, "")


def _script_cyrillic(ch: str) -> bool:
    return "CYRILLIC" in unicodedata.name(ch, "")


def is_emoji_component(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF
            or 0x2600 <= cp <= 0x27BF
            or cp in (0x2640, 0x2642, 0x2764, 0xFE0F))


def is_arabic_letter(ch: str) -> bool:
    return unicodedata.category(ch).startswith("L") and "ARABIC" in unicodedata.name(ch, "")


def suspicious_invisible_at(text: str, index: int) -> bool:
    ch=text[index]
    if ch not in ("\u200c", "\u200d"):
        return ch in "\u200b\u2060\ufeff\u00ad"
    before=text[index-1] if index else ""
    after=text[index+1] if index+1<len(text) else ""
    if ch=="\u200c" and before and after and is_arabic_letter(before) and is_arabic_letter(after):
        return False
    if ch=="\u200d" and before and after and is_emoji_component(before) and is_emoji_component(after):
        return False
    return True


def _unhide(text: str) -> str:
    return "".join(ch for i,ch in enumerate(text)
                   if not (ch in "\u200b\u200c\u200d\u2060\ufeff\u00ad"
                           and suspicious_invisible_at(text,i)))


def _translate_tags(text: str) -> str:
    return "".join(chr(ord(c)-0xE0000)
                   for c in text if 0xE0020<=ord(c)<=0xE007E)


def _apply(transform: str, raw: str) -> str:
    if transform == "NFKC":
        return unicodedata.normalize("NFKC", raw)
    if transform == "MIXED_SCRIPT_CONFUSABLE":
        def fold_word(match):
            word=match.group()
            if (any(_script_latin(c) for c in word)
                    and any(_script_cyrillic(c) for c in word)):
                return word.translate(CYRILLIC_TO_LATIN)
            return word
        return UNICODE_WORD.sub(fold_word,raw)
    if transform == "LETTER_SPACING":
        return LETTER_SPACING.sub(
            lambda match: re.sub(r"[ \t]","",match.group()),raw)
    if transform == "INVISIBLE_SEPARATORS":
        return _unhide(raw)
    if transform == "TAG_BLOCK_ASCII":
        return _translate_tags(raw)
    if transform == "HTML_ENTITIES":
        return unescape(raw)
    if transform == "BASE64_UTF8":
        binary = base64.b64decode(raw, validate=True)
        return binary.decode("utf8", errors="strict")
    raise ValueError("M2_UNKNOWN_TRANSFORMATION")


@dataclass(frozen=True)
class AttestedView:
    source_kind: Literal["VALUE", "KEY"]
    pointer: str
    source_view_id: str
    source_digest: str
    start: int
    end: int
    original_excerpt: str
    derived_text: str
    transform: str
    view_id: str
    offset_precision: Literal["TOKEN"] = "TOKEN"
    offset_map_verified: bool = True
    parent_pointer: str | None = None
    key: str | None = None

    def verify(self, context: AnalysisContext) -> bool:
        if (self.source_view_id != context.original.view_id
                or self.source_digest != context.original.sha256):
            raise ValueError("M2_SOURCE_IDENTITY_MISMATCH")
        if (not self.offset_map_verified or self.offset_precision != "TOKEN"
                or type(self.start) is not int or type(self.end) is not int
                or not (0 <= self.start < self.end)):
            raise ValueError("M2_SPAN_NOT_ATTESTED")
        if self.source_kind == "VALUE":
            if self.parent_pointer is not None or self.key is not None:
                raise ValueError("M2_VALUE_HAS_KEY_METADATA")
            Evidence(self.source_view_id,self.source_digest,self.pointer,
                     self.start,self.end,self.original_excerpt).verify(context.original)
        elif self.source_kind == "KEY":
            if self.parent_pointer is None or self.key is None:
                raise ValueError("M2_KEY_ORIGIN_MISSING")
            if self.pointer != self.parent_pointer+"/"+self.key.replace("~","~0").replace("/","~1"):
                raise ValueError("M2_KEY_POINTER_MISMATCH")
            if not any(path.pointer==self.parent_pointer and key==self.key
                       for path,key in context.key_inventory):
                raise ValueError("M2_UNKNOWN_SOURCE_KEY")
            if (self.end>len(self.key)
                    or self.key[self.start:self.end]!=self.original_excerpt):
                raise ValueError("M2_KEY_SPAN_MISMATCH")
        else:
            raise ValueError("M2_UNKNOWN_SOURCE_KIND")
        if _apply(self.transform,self.original_excerpt)!=self.derived_text:
            raise ValueError("M2_UNVERIFIED_TRANSFORMATION")
        if self.derived_text == self.original_excerpt:
            raise ValueError("M2_NO_TRANSFORMATION")
        if self.view_id != _identity(self):
            raise ValueError("M2_VIEW_TAMPERED")
        return True


def _identity(view: AttestedView) -> str:
    components=(view.source_digest,view.source_view_id,view.pointer,
                view.source_kind,str(view.start),str(view.end),
                view.original_excerpt,view.derived_text,view.transform)
    return "m2:"+sha256("\x00".join(components).encode("utf8")).hexdigest()


def _derive(kind: str,pointer: str,parent: str | None,key: str | None,
            text: str,start: int,end: int,transform: str,context: AnalysisContext) -> AttestedView:
    raw=text[start:end]
    derived=_apply(transform,raw)
    origin=context.original
    placeholder=AttestedView(kind,pointer,origin.view_id,origin.sha256,start,end,
                             raw,derived,transform,"",parent_pointer=parent,key=key)
    view=AttestedView(kind,pointer,origin.view_id,origin.sha256,start,end,
                      raw,derived,transform,_identity(placeholder),
                      parent_pointer=parent,key=key)
    view.verify(context)
    return view


def _candidates(text: str):
    # Bounded deterministic views, each mapped to the ORIGINAL enclosing
    # span. No claim of exact offsets *inside* derived Unicode characters.
    normalized=unicodedata.normalize("NFKC",text)
    if normalized!=text:
        yield 0,len(text),"NFKC"
    # Fast ASCII path: avoid per-word Unicode-name lookups unless the
    # text actually contains Cyrillic characters. This cannot suppress
    # a mixed-script attack because every Cyrillic char is non-ASCII.
    if (any(_script_cyrillic(ch) for ch in text if ord(ch)>127)
            and any((len(match.group())<=256
                     and any(_script_latin(c) for c in match.group())
                     and any(_script_cyrillic(c) for c in match.group())
                     and match.group().translate(CYRILLIC_TO_LATIN)!=match.group())
                    for match in UNICODE_WORD.finditer(text))):
        yield 0,len(text),"MIXED_SCRIPT_CONFUSABLE"
    if LETTER_SPACING.search(text):
        yield 0,len(text),"LETTER_SPACING"
    if (any(ch in text for ch in "\u200b\u200c\u200d\u2060\ufeff\u00ad")
            and _unhide(text)!=text):
        yield 0,len(text),"INVISIBLE_SEPARATORS"
    for match in TAG_BLOCK.finditer(text):
        if match.start()>0 and text[match.start()-1]=="\U0001f3f4":
            continue  # Emoji subdivision-flag tag sequence, not ASCII concealment
        yield match.start(),match.end(),"TAG_BLOCK_ASCII"
    if HTML_ENTITY.search(text):
        if unescape(text)!=text:
            yield 0,len(text),"HTML_ENTITIES"
    for match in BASE64_TOKEN.finditer(text):
        token=match.group()
        try:
            decoded=_apply("BASE64_UTF8",token)
        except (ValueError, UnicodeError, base64.binascii.Error):
            continue
        if (8<=len(decoded)<=MAX_SOURCE_CHARS and decoded.isprintable()
                and decoded!=token):
            yield match.start(),match.end(),"BASE64_UTF8"


def collect_derived_views(context: AnalysisContext) -> tuple[tuple[AttestedView,...],tuple[str,...]]:
    """M1 values+keys -> only bounded mechanically attestable M2 views.

    Coverage limitations are explicit; caller must not interpret no views
    as proof that all obfuscation forms were inspected.
    """
    surfaces=[("VALUE",f.pointer,None,None,f.text) for f in context.source_fields]
    for path,key in context.key_inventory:
        p=path.pointer
        pointer=p+"/"+key.replace("~","~0").replace("/","~1")
        surfaces.append(("KEY",pointer,p,key,key))
    result=[]
    limits=[]
    aggregate=0
    if len(surfaces)>256:
        limits.append("M2_SOURCE_FIELD_BUDGET")
    for kind,pointer,parent,key,text in surfaces[:256]:
        if len(text)>MAX_SOURCE_CHARS:
            limits.append("M2_SOURCE_CHAR_BUDGET")
            continue
        count=0
        for start,end,transform in _candidates(text):
            if count>=MAX_DERIVED_PER_ORIGIN:
                limits.append("M2_PER_SOURCE_VIEW_BUDGET")
                break
            if len(result)>=MAX_DERIVED_VIEWS:
                limits.append("M2_TOTAL_DERIVED_VIEW_BUDGET")
                break
            view=_derive(kind,pointer,parent,key,text,start,end,transform,context)
            if aggregate+len(view.derived_text)>MAX_AGGREGATE_DERIVED_CHARS:
                limits.append("M2_AGGREGATE_DERIVED_CHAR_BUDGET")
                break
            result.append(view)
            aggregate+=len(view.derived_text)
            count+=1
        if len(result)>=MAX_DERIVED_VIEWS:
            break
    return tuple(result),tuple(dict.fromkeys(limits))
