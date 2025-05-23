# Graph generation

Package `graph` contains the generated code that is used in tests.
The `graphupdater` tool reads `.topo` files and generates the graphs from them.

Since interface IDs are of type `uint16`, the ability to generate unique IDs
from the info in `.topo` file deterministically and without magic tricks is
limited. The magic trick of choice is usage of static interface IDs. They are
stored in the file `ifaceids.go` and should be updated manually if a new
interface is needed.

Everything else is generated. All possible links are generated and written to
`links_gen.go`. Other `*_gen.go` files are representing the graphs.
