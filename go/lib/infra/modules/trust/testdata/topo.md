Cross signatures are not implemented so ISDs exist in isolation. The
graph for this test file (in graph's package format) is outlined below.

```
Nodes: []string{
    "1-ff00:0:1", "1-ff00:0:2", "1-ff00:0:3",
    "2-ff00:0:4", "2-ff00:0:5", "2-ff00:0:6",
    "3-ff00:0:7", "3-ff00:0:8", "3-ff00:0:9",
    "4-ff00:0:a", "4-ff00:0:b", "4-ff00:0:c",
    "5-ff00:0:d", "5-ff00:0:e", "5-ff00:0:f",
}
Edges: []EdgeDesc{
    {"1-ff00:0:1", 1121, "2-ff00:0:4", 2111},
    {"1-ff00:0:1", 1131, "3-ff00:0:7", 3111},
    {"1-ff00:0:1", 1141, "4-ff00:0:a", 4111},
    {"2-ff00:0:4", 2131, "3-ff00:0:7", 3121},
    {"2-ff00:0:4", 2151, "5-ff00:0:d", 5121},
    {"1-ff00:0:1", 1112, "1-ff00:0:2", 1211},
    {"2-ff00:0:4", 2122, "2-ff00:0:5", 2221},
    {"3-ff00:0:7", 3132, "3-ff00:0:8", 3231},
    {"4-ff00:0:a", 4142, "4-ff00:0:b", 4241},
    {"5-ff00:0:d", 5152, "5-ff00:0:e", 5251},
    {"1-ff00:0:1", 1113, "1-ff00:0:3", 1311},
    {"2-ff00:0:4", 2123, "2-ff00:0:6", 2321},
    {"3-ff00:0:7", 3133, "3-ff00:0:9", 3331},
    {"4-ff00:0:a", 4143, "4-ff00:0:c", 4341},
    {"5-ff00:0:d", 5153, "5-ff00:0:f", 5351},
}
```

CoreASes: lower 2 ASes in each ISD
NonCoreAses: upper AS in each ISD
Issuer for NonCore: first AS for ISDs 1, 2 and second AS for ISDs 3, 4, 5
