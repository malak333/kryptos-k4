# Source Packet

Accessed: 2026-05-20

This packet records the public sources used by the CLI data model. It intentionally stores summaries and links only; it does not store claimed full K4 plaintext, leaked/archive-discovered plaintext, or paid/private archive material.

| Source ID | Type | URL | Archive Status | Allowed Use | Quote-Free Summary |
| --- | --- | --- | --- | --- | --- |
| `cia-artifact` | primary | https://www.cia.gov/legacy/museum/artifact/kryptos/ | Not locally archived | Public installation and unresolved-section facts | Establishes Kryptos as a CIA artwork with a still-unsolved fourth section. |
| `cia-sculpture` | primary | https://www.cia.gov/legacy/headquarters/kryptos-sculpture/ | Not locally archived | Public sculpture/chart/K4 context | Records public sculpture context, the chart/table component, and CIA's 97-character K4 framing. |
| `elonka-kryptos` | reference | https://www.elonka.com/kryptos/ | Not locally archived | Public ciphertext and public clue summary | Provides the public K4 ciphertext transcription and public clue-position summary used for anchors. |
| `histocrypt-2021-bean` | academic | https://ecp.ep.liu.se/index.php/histocrypt/article/view/153 | Not locally archived | Cryptodiagnosis context only | Supplies published cryptodiagnosis context for one-to-one and Gromark-like hypothesis tests. |
| `scientific-american-2025` | major-reporting | https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/ | Not locally archived | Public clue and Berlin World Clock context | Summarizes public 2025 clue context, including the Berlin World Clock clarification. |
| `ap-2025-auction` | major-reporting | https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/ | Not locally archived | Archive-sale context only | Records the public auction context and Sanborn's distinction between archive discovery and decipherment. |
| `ap-2025-archive-sale` | major-reporting | https://apnews.com/article/kryptos-jim-sanborn-auction-cia-secret-code-cb8ee8554ca473910cbd0592f8bdb350 | Not locally archived | Archive-sale context only | Records the public sale outcome as historical context while excluding archive-discovered plaintext. |
| `kryptosbot-sanborn-papers-2026` | community-research-archive | https://kryptosbot.com/archive/ | Not locally archived | Archive-research context only | Curated public notes from a 2026 Smithsonian Sanborn papers research visit; useful for future preregistration context only, not scored plaintext or candidate evidence. |

## Boundary

- Do not add claimed full plaintext.
- Do not add private auction/archive material.
- Do not add archive-discovered plaintext from reporting or auction materials.
- Do not convert community claims into facts.
- Do not convert community archive-research interpretations into scored observations
  unless an independent preregistration and source-backed observation file define
  the exact target first.
- If archive URLs or local source snapshots are added later, update both this file and the `Source` records in `src/data.rs`.
