package tmpl

const sampleTopo = `--- # Sample topology
ASes:
  "1-ff00:0:a":
    core: true
    voting: true
    authoritative: true
    cert_issuer: 1-ff00:0:c
  "1-ff00:0:b":
    voting: true
    cert_issuer: 1-ff00:0:c
  "1-ff00:0:c":
    voting: true
    issuing: true

  "2-ff00:0:e":
    core: true
    voting: true
    authoritative: true
    issuing: true
  "2-ff00:0:f":
    core: true
    voting: true
    authoritative: true
    issuing: true
`
