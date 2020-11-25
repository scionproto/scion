package hiddenpathtest

import "github.com/scionproto/scion/go/hidden_path_srv/internal/hiddenpath"

// MustParseHPGroupId parses s and returns the corresponding hiddenpath.GroupId object.
// It panics if s is not a valid GroupId representation
func MustParseHPGroupId(s string) hiddenpath.GroupId {
	id := hiddenpath.GroupId{}
	err := id.UnmarshalText([]byte(s))
	if err != nil {
		panic(err)
	}
	return id
}
