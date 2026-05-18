# PoC for adding additional fields to TRC

## Installing latest scion-pki

```bash
curl -1sLf -O 'https://dl.cloudsmith.io/public/anapaya/public/raw/versions/latest/scion-pki'
```

(Make executable and put on PATH)

## Generating artifacts

With additional fields:

```bash
go run ./scion-pki/cmd/scion-pki/ testcrypto -t topology/default.topo -o /tmp/trc/additional-fields
go run ./scion-pki/cmd/scion-pki/ testcrypto update -o /tmp/trc/additional-fields
```

Without additional fields:

```bash
scion-pki testcrypto -t topology/default.topo -o /tmp/trc/original
scion-pki testcrypto update -o /tmp/trc/original
```

Copy relevant artifacts to `trcs`:

```bash
mkdir -p trc/{additional-fields,original}
cp /tmp/trc/additional-fields/trcs/ISD1* trc/additional-fields/
cp /tmp/trc/original/trcs/ISD1* trc/original/
```

## Verify backwards compatibility

Check that the new CPPKI library can still verify the original TRC:

```bash
go run ./scion-pki/cmd/scion-pki/ trc verify trc/original/ISD1-B1-S2.trc --anchor trc/original/ISD1-B1-S1.trc
```

## Verify forward compatibility

Check that the original CPPKI library can verify the new TRC:

```bash
scion-pki trc verify trc/additional-fields/ISD1-B1-S2.trc --anchor trc/additional-fields/ISD1-B1-S1.trc
```

## Inspect data

```bash
go run ./scion-pki/cmd/scion-pki/ trc inspect trc/additional-fields/ISD1-B1-S2.trc | grep desc -A 1
```

```yaml
description: Testcrypto TRC for ISD 1
description_language: en
localized_descriptions:
  de: Testcrypto TRC für ISD 1
```

```bash
go run ./scion-pki/cmd/scion-pki/ trc extract payload trc/additional-fields/ISD1-B1-S2.trc -o trc/payload
```

```bash
openssl asn1parse -inform DER -i -in trc/payload | tail -n 7
```

```text
 4713:d=1  hl=2 l=  35 cons:  cont [ 0 ]        
 4715:d=2  hl=2 l=  33 cons:   SEQUENCE          
 4717:d=3  hl=2 l=  31 cons:    SEQUENCE          
 4719:d=4  hl=2 l=   2 prim:     PRINTABLESTRING   :de
 4723:d=4  hl=2 l=  25 prim:     UTF8STRING        :Testcrypto TRC für ISD 1
 4750:d=1  hl=2 l=   4 cons:  cont [ 1 ]        
 4752:d=2  hl=2 l=   2 prim:   PRINTABLESTRING   :en
```
