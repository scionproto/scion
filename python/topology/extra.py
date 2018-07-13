
import toml

v1 = "sd-test"
v2 = "Topology"
v3 = "../../gen/ISD1/ASf00_0_133/endhost/"
v4 = "dir/sciond.log"
v5 = "debug"
v6 = "crit"
v7 = "../../gen/ISD1/ASff00_0_133/endhost/trust.db"
v8 = "/run/shm/sciond/default.sock"
v9 = "/run/shm/scion/unix.sock"
v10 = "1-ff00:0:133,[127.0.0.1]:60001"
v11 = "../../gen/ISD1/ASff00_0_133/endhost/path.db"

config = {
    "general": {
        "ID": v1,
        "Topology": v2,
        "ConfigDir": v3,
    },
    "logging": {
        "file": {
            "File": v4,
            "Level": v5,
        },
        "console": {
            "Level": v6,
        },
    },
    "trust": {
        "TrustDB": v7,
    },
    "sd": {
        "Reliable": v8,
        "Unix": v9,
        "Public": v10,
        "PathDB": v11,
    },
}

text_content = toml.dumps(config)
print(text_content)
