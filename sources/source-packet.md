# Source Packet

Accessed: 2026-05-20

This packet records the public sources used by the CLI data model. It intentionally stores summaries and links only; it does not store claimed full K4 plaintext, leaked/archive-discovered plaintext, or paid/private archive material.

| Source ID | Type | URL | Archive Status | Allowed Use |
| --- | --- | --- | --- | --- |
| `cia-artifact` | primary | https://www.cia.gov/legacy/museum/artifact/kryptos/ | Not locally archived | Public installation and unresolved-section facts |
| `cia-sculpture` | primary | https://www.cia.gov/legacy/headquarters/kryptos-sculpture/ | Not locally archived | Public sculpture/chart/K4 context |
| `elonka-kryptos` | reference | https://www.elonka.com/kryptos/ | Not locally archived | Public ciphertext and public clue summary |
| `histocrypt-2021-bean` | academic | https://ecp.ep.liu.se/index.php/histocrypt/article/view/153 | Not locally archived | Cryptodiagnosis context only |
| `scientific-american-2025` | major-reporting | https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/ | Not locally archived | Public clue and Berlin World Clock context |
| `ap-2025-auction` | major-reporting | https://www.ap.org/news-highlights/spotlights/2025/kryptos-final-code-remains-unsolved-the-cia-sculptures-creator-is-auctioning-the-solution/ | Not locally archived | Archive-sale context only |

## Boundary

- Do not add claimed full plaintext.
- Do not add private auction/archive material.
- Do not convert community claims into facts.
- If archive URLs or local source snapshots are added later, update both this file and the `Source` records in `src/data.rs`.
