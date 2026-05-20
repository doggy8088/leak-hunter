# Taiwan PDPA-Oriented Personal-Data Pattern Analysis for leak-hunter

## Executive Summary

Taiwan’s Personal Data Protection Act (PDPA) is broad: Article 2(1) covers direct identifiers, contact info, financial conditions, and any data that can directly or indirectly identify a person; Article 6 separately elevates medical, healthcare, genetic, sex-life/orientation, physical-exam, and criminal-record data to sensitive status.[^1][^2] For `leak-hunter`, the best near-term rules are deterministic Taiwan-specific identifiers with validation: National ID, UI/ARC/APRC numbers, mobile numbers, e-invoice mobile barcode, and citizen digital certificate numbers.[^3][^4] Passport, landline, address/postcode, and bank account detection should stay contextual because they are either ambiguous or lack checksum support.[^5][^6] BAN, e-invoice number, love code, household registration number, and vehicle plates should not be treated as standalone personal-data rules.[^7][^8]

## Legal Scope under Taiwan PDPA

- **Direct personal data:** name, DOB, National ID, passport number, contact info, financial conditions, and other identifying data.[^1]
- **Sensitive personal data (Art. 6):** medical records, healthcare data, genetic data, sex life/orientation, physical-examination records, criminal records.[^2]
- **Operational implication:** pattern-match what is deterministic; use labels, co-occurrence, or keyword windows for indirect identifiers.[^1][^2]

## Pattern Taxonomy

### Deterministic identifiers to implement now

| Candidate rule | Rationale | Pattern / validation | Precision risk | Recommendation |
|---|---|---|---|---|
| Taiwan National ID | Explicit PDPA personal data; stable checksum | `[A-Z][12]\d{8}` + checksum | Low with checksum | **Implement now**[^3] |
| UI/ARC/APRC number | Person-linked resident identifier; same checksum family | old: `[A-Z][A-D]\d{8}`; new: `[A-Z][89][0-9]\d{7}` + checksum | Low with checksum | **Implement now**[^3] |
| Taiwan mobile phone | PDPA contact info; highly distinctive `09` prefix | `09\d{8}` or `+8869\d{8}` | Low | **Implement now**[^5] |
| E-invoice mobile barcode | Taiwan-specific, person-linked carrier | `/[A-Z0-9.+\-]{7}` | Low-medium | **Implement now**[^4] |
| Citizen digital certificate | Person-linked e-government credential | `[A-Z]{2}\d{14}` | Medium | **Implement now**[^4] |

### Contextual-only patterns

| Candidate rule | Rationale | Pattern / validation | Precision risk | Recommendation |
|---|---|---|---|---|
| Passport number | Explicit PDPA item, but public formats conflict | keyword-gated `[A-Z]\d{8}` / legacy variants | Medium-high | **Contextual only**[^9] |
| Landline phone | Contact info, but variable area codes | `0[2-9]\d{1,3}[-\s]?\d{6,8}` with phone keywords | Medium | **Contextual only**[^5] |
| Bank account | PDPA “financial conditions”; no national checksum | label-anchored digits + bank-code lookup | High | **Contextual only**[^7] |
| Postal address / postcode | Contact info, but numeric codes alone are noisy | Chinese address tokens + postal code | Medium | **Contextual only**[^5] |
| Name + DOB + address | Compound quasi-identifier | window-based co-occurrence | High | **Phase 3**[^10] |

### Rely on existing global rules

| Candidate rule | Rationale | Pattern / validation | Precision risk | Recommendation |
|---|---|---|---|---|
| Credit card PAN | Existing PCI/Luhn coverage already fits | standard PAN + Luhn | Low | **Reuse existing rule**[^7] |
| Email | Existing generic email rule is enough | RFC-style regex; `.tw` as risk boost | Low-medium | **Reuse existing rule**[^5] |

### Out-of-scope / do-not-implement

- **BAN / 統一編號** as a standalone personal-data rule: organizational identifier, not person-specific.
- **E-invoice number**: document identifier, not personal data.
- **Love code**: charity identifier.
- **Household registration number / 戶號**: household-level, not individual.
- **Vehicle plates**: not a standalone PDPA personal-data rule; too noisy unless tied to owner data.[^7][^8]

## Sensitive personal data (Art. 6) operationalization

| Category | Practical markers | Detection method | Severity |
|---|---|---|---|
| Medical records / healthcare / physical exam | `.dcm`, HL7 `MSH|^~\&|`, FHIR `resourceType`, CDA XML, diagnosis/lab/prescription keys | file-type + structural regex + schema keys | Critical |
| Genetic data | `.vcf`, `.fasta`, `.fastq`, `.sam`, `##fileformat=VCFv4`, `#CHROM` | extension + headers + rsID clusters | Critical |
| Criminal records | `犯罪前科`, `不起訴`, `緩起訴`, Taiwan court case-number patterns | Chinese keyword + case-number regex | High-Critical |
| Sex life / orientation | `sexual_orientation`, `性取向`, LGBTQ+/HIV/STI fields | schema-key + keyword heuristic | Critical |
| Biometric data | `.wsq`, `<BIR>`, `face_encoding`, `fingerprint_template`, `iris_template` | extension + schema-key + binary/float-array heuristic | High (Critical in health context) |

Biometrics are a Taiwan nuance: they are personal data under Article 2(1), but not explicitly enumerated in Article 6 like GDPR biometrics. Treat them as high-risk, and elevate to critical when paired with health-check or enrollment context.[^2][^10]

## Recommended phased roadmap for leak-hunter

1. **Phase 1 — high precision now:** National ID, UI/ARC/APRC, mobile phone, e-invoice mobile barcode, citizen digital certificate.
2. **Phase 2 — contextual heuristics:** passport, landline, bank account, address/postcode, Art. 6 keyword heuristics.
3. **Phase 3 — compound exposure:** name + DOB + address co-occurrence, ROC calendar normalization, field-label scoring, cross-field risk boosts.
4. **Reuse existing rules:** credit card Luhn and email; add `.tw` as a risk booster, not a new standalone rule.
5. **Skip by default:** BAN, e-invoice number, love code, household registration number, vehicle plates.

## Confidence Assessment

- **High confidence:** PDPA scope, National ID/UI/mobile/e-invoice barcode/citizen certificate formats, Art. 6 category list, and the “do not implement” exclusions.[^1][^2][^3][^4]
- **Medium confidence:** passport, landline, bank account, address/postcode, and biometric heuristics because they rely on context or have more false positives.[^5][^7][^9][^10]
- **Known disagreement:** passport format is not stable across public sources, so treat it as keyword-gated only; citizen digital certificate has format confirmation from open-source validation, but no checksum.[^4][^9]
- **Implementation risk:** checksum validation is essential for Taiwan ID/UI; without it, false positives rise sharply.[^3]

## Footnotes

[^1]: Taiwan PDPA official text, Article 2(1) and related provisions: <https://law.moj.gov.tw/ENG/LawClass/LawAll.aspx?pcode=I0050021>
[^2]: Taiwan PDPA Enforcement Rules, especially Articles 3–4: <https://law.moj.gov.tw/ENG/LawClass/LawAll.aspx?pcode=I0050022>
[^3]: Taiwan National ID / UI number formats and checksum family: `src/id-card-number.ts` in <https://github.com/enylin/taiwan-id-validator>
[^4]: E-invoice mobile barcode and citizen digital certificate format findings: `src/e-invoice-mobile-barcode.ts` and `src/citizen-digital-certificate-number.ts` in <https://github.com/enylin/taiwan-id-validator>
[^5]: Taiwan contact and address patterns: <https://en.wikipedia.org/wiki/Telephone_numbers_in_Taiwan> and Taiwan locale pattern summaries in the research outputs
[^6]: Taiwan postal / landline / contextual heuristic recommendations: `docs/risk-model.md` and the research outputs gathered for this report
[^7]: Taiwan financial-pattern recommendations, including BAN exclusions and bank-account context gating: Taiwan PDPA Article 2(1) and the research outputs gathered for this report
[^8]: Exclusions and out-of-scope items (BAN, e-invoice number, love code, household registration, vehicle plates): the research outputs gathered for this report
[^9]: Passport format disagreement and keyword-gated recommendation: the research outputs gathered for this report
[^10]: Art. 6 operationalization, sensitive-data file markers, and phased roadmap: Taiwan PDPA Enforcement Rules Article 4 and the research outputs gathered for this report
