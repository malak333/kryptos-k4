# Anchor-Implied Key Language Test

This is not a claimed solution.

English corpus: `carter-v1.txt` (141196 training letters, 141123 held-out windows)
anchor runs: [13, 11]
configurations: 8103
threshold: -9.4825 (quantile 0.001 of held-out English windows; English median -7.6149)
uniform random median: -11.7449; pass rate at threshold: 1.40e-4 over 200000 samples (seed 1)
compatible configurations: 1 (expected by chance: 1.13)

| Tableau | Implied key | Score | English quantile |
| --- | --- | ---: | ---: |
| quagmire-iv vigenere pt=enigma ct=carter key=pt | CDHIRMEFADCNE FYEDNICKTHE | -9.4110 | 1.25e-3 |
| quagmire-iv vigenere pt=enigma ct=urania key=pt | FFFIRMEDTHDNE XYEDSTDKVHN | -9.4995 | 9.57e-4 |
| quagmire-iv vigenere pt=weltzeituhr ct=langley key=ct | DQVSZXDOUNEWP REDTONGWPYW | -9.8511 | 4.11e-4 |
| quagmire-iv beaufort pt=worldclock ct=urania key=pt | QUTMBSSUMSTHI GASYAFTRFVS | -9.8551 | 4.04e-4 |
| quagmire-iv vigenere pt=urania ct=lodestone key=pt | AYURMAOZVNKHG ROODRAGHTHA | -9.9448 | 3.26e-4 |
| quagmire-iv variant-beaufort pt=layertwo ct=magnetic key=pt | PHEDAKIHDAIYG TTITCHCAVPE | -9.9900 | 2.55e-4 |
| quagmire-iv vigenere pt=tutankhamun ct=scheidt key=pt | ZFZVLAYRETEMT CJYMRNMERDC | -9.9944 | 2.41e-4 |
| quagmire-iv variant-beaufort pt=weltzeituhr ct=lodestone key=ct | PCEBLOPFOMUQZ SEPALIVECUO | -10.0379 | 2.13e-4 |
| quagmire-iv variant-beaufort pt=enigma ct=tutankhamun key=pt | PQZYFWEECONYZ GIESINNOGQD | -10.0397 | 2.13e-4 |
| quagmire-iv variant-beaufort pt=memory ct=tutankhamun key=pt | NNMZXGIEDLEZM RRITINENPNG | -10.0627 | 2.13e-4 |
| quagmire-iv vigenere pt=memory ct=undergruund key=ct | CFINDOLHORCUZ VXLACRCHBHZ | -10.0658 | 2.13e-4 |
| quagmire-iv vigenere pt=pyramid ct=worldclock key=ct | OWERROMBDRLWZ EMMAMDAFSEQ | -10.0857 | 2.05e-4 |
| quagmire-iv beaufort pt=giza ct=tutankhamun key=pt | RRLODEHMLSEMN ECHEINKKGVO | -10.1171 | 1.91e-4 |
| quagmire-iv variant-beaufort pt=enigma ct=cairo key=pt | SSPYHXNQVRTEN RINSFDTOBRE | -10.1235 | 1.84e-4 |
| quagmire-iv variant-beaufort pt=mengenlehreuhr ct=palimpsest key=ct | NEPZDYEAKKRJK RIECEVESSDP | -10.1571 | 1.56e-4 |
| quagmire-iv vigenere pt=kryptos ct=enigma key=pt | XSELWEHGGMOFH NGHTTKUBTSF | -10.1625 | 1.56e-4 |
| quagmire-iv vigenere pt=shadow ct=sanborn key=ct | AJRANKYHANISC WMYDEBFHRGA | -10.1638 | 1.49e-4 |
| quagmire-iv vigenere pt=urania ct=shadow key=ct | HJSAMANZWAICB INNENPFIRIS | -10.1687 | 1.49e-4 |
| quagmire-iv variant-beaufort pt=lodestone ct=magnetic key=pt | RRHFKFEICOUGH TTETBOCOPRD | -10.1768 | 1.49e-4 |
| quagmire-iv beaufort pt=memory ct=pyramid key=pt | HTUNDTRVEISIJ VORHBGHKICO | -10.1791 | 1.49e-4 |
| quagmire-iv beaufort pt=giza ct=scheidt key=pt | PPLODEHMXQOST SCHEETSKXVW | -10.2185 | 1.20e-4 |
| quagmire-iv vigenere pt=undergruund ct=worldclock key=ct | AXERPRIBKBWWZ EUIBESAGTES | -10.2433 | 1.06e-4 |
| quagmire-iv variant-beaufort pt=digetal ct=mengenlehreuhr key=ct | PEIBWXEYAMOMD HHEDUTAUGPX | -10.2439 | 1.06e-4 |
| quagmire-iv vigenere pt=pyramid ct=howardcarter key=pt | YHGRARNFIRGYP FLNBROCFSFP | -10.2444 | 1.06e-4 |
| quagmire-iii variant-beaufort pt=invisible ct=invisible key=pt | WVFQDYVNGURIP SCVSEAREEPI | -10.2606 | 9.21e-5 |

A configuration is compatible if its anchor-implied key scores at least as English-like as the given quantile of held-out English windows. Compare compatible with expected_compatible_by_chance; a compatible configuration is a lead to test, not a decryption.

promoted: false
