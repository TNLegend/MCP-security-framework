"""Conservative *coverage* hints for English-first M3 rules.

NOT a language identifier, translation engine, attack classifier, or BLOCK
predicate. Latin-script text cannot be assumed English. A possible unsupported
language is reported as a coverage limitation with a per-field ledger entry.
"""
from __future__ import annotations
import re
import unicodedata

# These lexemes are high-specificity clues from previously exposed diagnostics,
# not attack keywords. Do not infer maliciousness or a full language label.
FRENCH_CUES = re.compile(
    r"\b(?:ignorer|ignorez|précédentes?|consignes?|sécurité|utilisateur|"
    r"veuillez|réponse|fournissez|envoyez|auparavant|"
    r"indications?|données|secrètes?)\b",re.I)
GERMAN_CUES = re.compile(
    r"\b(?:ignoriere|vorherigen|sicherheitsanweisungen|"
    r"zugangsdaten|anweisungen|benutzer|antwort|sende|"
    r"geheimnisse|werkzeug|ausgabe|prüfen)\b",re.I)
OTHER_SCRIPT = ("CYRILLIC","GREEK","ARABIC","HEBREW","CJK",
                "HIRAGANA","KATAKANA","HANGUL","DEVANAGARI")

def language_scope(text: str) -> str:
    """Return uncertainty, NEVER a guaranteed language identity.

    - SCRIPT_UNVERIFIED: letter contains a non-Latin script.
    - LATIN_NON_ENGLISH_CUES: >=2 strong French/German lexical cues or one
      clear German-specific compound from the exposed diagnostic.
    - ENGLISH_FIRST_NO_LANGUAGE_ID: all remaining text is UNVERIFIED, not
      automatically certified English. QA should not call it fully covered.
    """
    for ch in text[:16000]:
        if ord(ch)<128 or not unicodedata.category(ch).startswith("L"):
            continue
        name=unicodedata.name(ch,"")
        if any(label in name for label in OTHER_SCRIPT):
            return "SCRIPT_UNVERIFIED"
    french=len(FRENCH_CUES.findall(text[:16000]))
    german=len(GERMAN_CUES.findall(text[:16000]))
    if french>=2 or german>=2 or re.search(r"\bsicherheitsanweisungen\b",text,re.I):
        return "LATIN_NON_ENGLISH_CUES"
    return "ENGLISH_FIRST_NO_LANGUAGE_ID"
