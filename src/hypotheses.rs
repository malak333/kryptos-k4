use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hypothesis {
    pub id: &'static str,
    pub priority: u8,
    pub name: &'static str,
    pub supporting_facts: &'static str,
    pub required_assumptions: &'static str,
    pub falsification_test: &'static str,
    pub risk: &'static str,
}

pub fn hypotheses() -> Vec<Hypothesis> {
    vec![
        Hypothesis {
            id: "H1",
            priority: 1,
            name: "Gromark-like or running-key additive system",
            supporting_facts: "Bean's HistoCrypt abstract reports one-to-one evidence and identifies Gromark as a possible method family.",
            required_assumptions: "K4 uses a keyed alphabet and running numeric key stream or adjacent additive construction.",
            falsification_test: "Derive public-anchor key fragments and check whether they can coexist under Gromark-style recurrence rules.",
            risk: "Flexible additive models can be overfit to known anchors.",
        },
        Hypothesis {
            id: "H2",
            priority: 2,
            name: "Kryptos-alphabet Vigenere descendant with added transformation",
            supporting_facts: "K1 and K2 use Vigenere-like mechanics with the Kryptos alphabet.",
            required_assumptions: "K4 preserves family resemblance while adding a new key schedule, route, or preprocessing layer.",
            falsification_test: "Compute anchor-implied key letters for supported alphabets and reject structureless fragments.",
            risk: "Prior-method bias may obscure a deliberate departure from K1/K2.",
        },
        Hypothesis {
            id: "H3",
            priority: 3,
            name: "Hybrid substitution plus route or matrix transposition",
            supporting_facts: "CIA says earlier sections combine chart and matrix systems; K3 uses transposition-like behavior.",
            required_assumptions: "K4 combines a one-to-one layer with a stable route or matrix permutation.",
            falsification_test: "Pre-register route families and test whether one permutation improves fragment coherence.",
            risk: "Route spaces are large and can create false positives.",
        },
        Hypothesis {
            id: "H4",
            priority: 4,
            name: "Berlin World Clock, compass, or directional mechanism",
            supporting_facts: "Sanborn clarified BERLINCLOCK points to Berlin's World Clock; known anchors include EAST and NORTHEAST.",
            required_assumptions: "Clock or compass data contributes to key generation, ordering, or validation.",
            falsification_test: "Define source-derived numeric sequences before checking them against anchor fragments.",
            risk: "The clock clue is highly ambiguous without a pre-registered mapping.",
        },
        Hypothesis {
            id: "H5",
            priority: 5,
            name: "Egypt 1986 or Berlin Wall 1989 event-timeline key material",
            supporting_facts: "2025 reporting says both events figure in the solution.",
            required_assumptions: "The events provide constrained key words, dates, places, routes, or ordering rules.",
            falsification_test: "Pre-register a small event-key list from strict sources and test without ad hoc expansion.",
            risk: "Underspecified source material invites unconstrained key hunting.",
        },
    ]
}
