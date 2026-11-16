"""M3 English-first *coverage policy*, not a malware or language verdict.

Only positive English lexical evidence allows the English rules to be
marked INSPECTED in their stated limited scope. Otherwise NOT_ANALYZED,
without claiming the text is malicious or even establishing which language
it is. This is not a calibrated language identifier.
"""
from __future__ import annotations
import re
import unicodedata

FRENCH_CUES=re.compile(
    r"\b(?:ignorer|ignorez|consignes|précédentes|sécurité|utilisateur|"
    r"veuillez|réponse|fournissez|envoyez|données)\b",re.I)
GERMAN_CUES=re.compile(
    r"\b(?:ignoriere|vorherigen|sicherheitsanweisungen|zugangsdaten|"
    r"anweisungen|benutzer|antwort|sende|geheimnisse|werkzeug)\b",re.I)
SPANISH_CUES=re.compile(
    r"\b(?:ignora|ignorar|anteriores|instrucciones|seguridad|"
    r"contraseña|contraseñas|usuario|enviar|envía)\b",re.I)
ITALIAN_CUES=re.compile(
    r"\b(?:ignora|ignorare|precedenti|istruzioni|sicurezza|"
    r"utente|risposta|invia|credenziali)\b",re.I)
ENGLISH_WORDS=re.compile(
    r"\b(?:the|this|that|tool|tools|returns?|returning|when|called|calling|"
    r"answer|answering|call|user|users|previous|instructions|security|"
    r"please|include|ignore|system|should|must|your|with|from|search|"
    r"files|filesystems?|result|results|output|response|if|and|for|"
    r"using|provides|provide|data|source|sources)\b",re.I)
OTHER_SCRIPT=("CYRILLIC","GREEK","ARABIC","HEBREW","CJK",
              "HIRAGANA","KATAKANA","HANGUL","DEVANAGARI")

def language_scope(text: str) -> str:
    sample=text[:16000]
    for ch in sample:
        if ord(ch)<128 or not unicodedata.category(ch).startswith("L"):
            continue
        name=unicodedata.name(ch,"")
        if any(s in name for s in OTHER_SCRIPT):
            return "SCRIPT_UNVERIFIED"
    if (len(FRENCH_CUES.findall(sample))>=2 or
        len(GERMAN_CUES.findall(sample))>=2 or
        len(SPANISH_CUES.findall(sample))>=2 or
        len(ITALIAN_CUES.findall(sample))>=2):
        return "LATIN_NON_ENGLISH_CUES"
    # English rules are technically attempted only when at least two distinct
    # English context words are visible. This NEVER certifies English and
    # cannot be reused as a general-purpose language ID.
    english={m.group().lower() for m in ENGLISH_WORDS.finditer(sample)}
    if len(english)>=2:
        return "ENGLISH_POSITIVE_CUES_NOT_CERTIFIED"
    return "LANGUAGE_UNVERIFIED_NO_ENGLISH_EVIDENCE"
