# Pathdb dump

Debug tool that dumps the contents of a sqlite3 path DB.
Example run, with a Tiny local topology:

```bash
$ ./bin/pathdb_dump -db gen-cache/cs1-ff00_0_111-1.path.db -t
down    1-ff00:0:110 2>1 1-ff00:0:112   Updated: 13.78888572s   : Expires in: 5h59m4.159253713s
up      1-ff00:0:110 1>41 1-ff00:0:111  Updated: 559.659282ms   : Expires in: 5h59m26.159224989s
```

For complete options:

```bash
./bin/pathdb_dump -h
```
