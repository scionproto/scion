Cross signatures are not implemented so ISDs exist in isolation. The
graph for this test file (in graph's package format) is outlined below. For
readability, the AS numbers are offset by 4_300_000_000. The test file uses
actual numbers.

```
Nodes: []string{
    "1-1", "1-2", "1-3",
    "2-4", "2-5", "2-6",
    "3-7", "3-8", "3-9", 
    "4-10", "4-11", "4-12", 
    "5-13", "5-14", "5-15", 
}
Edges: []EdgeDesc{
    {"1-1", 1121, "2-4", 2111},
    {"1-1", 1131, "3-7", 3111},
    {"1-1", 1141, "4-10", 4111},
    {"2-4", 2131, "3-7", 3121},
    {"2-4", 2151, "5-13", 5121},
    {"1-1", 1112, "1-2", 1211},
    {"2-4", 2122, "2-5", 2221},
    {"3-7", 3132, "3-8", 3231},
    {"4-10", 4142, "4-11", 4241},
    {"5-13", 5152, "5-14", 5251},
    {"1-1", 1113, "1-3", 1311},
    {"2-4", 2123, "2-6", 2321},
    {"3-7", 3133, "3-9", 3331},
    {"4-10", 4143, "4-12", 4341},
    {"5-13", 5153, "5-15", 5351},
}
```

CoreASes: lower 2 ASes in each ISD
NonCoreAses: upper AS in each ISD
Issuer for NonCore: first AS for ISDs 1, 2 and second AS for ISDs 3, 4, 5
