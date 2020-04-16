// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// debug tool to dump the contents of a sqlite path DB.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/proto"
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while executing: %v\n", err)
		os.Exit(1)
	}
}

func realMain() error {
	filename := flag.String("db", "", "Sqlite DB file (optional)")
	showTimestamps := flag.Bool("t", false, "Show update and expiration times")
	version := flag.Bool("version", false, "Output version information and exit.")
	flag.Parse()
	var err error

	if *version {
		fmt.Print(env.VersionInfo())
		os.Exit(0)
	}
	if *filename == "" {
		*filename, err = defaultDBfilename()
		if err != nil {
			return err
		}
	}
	db, err := sqlite.New(*filename)
	if err != nil {
		return err
	}
	defer db.Close()

	ch, err := db.GetAll(context.Background())
	if err != nil {
		return err
	}
	var segments []segment
	for res := range ch {
		if res.Err != nil {
			return err
		}
		seg, err := newSegment(res.Result)
		if err != nil {
			return err
		}
		segments = append(segments, seg)
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].lessThan(&segments[j])
	})
	for _, seg := range segments {
		fmt.Println(seg.toString(*showTimestamps))
	}
	return nil
}

type asIface struct {
	IA    addr.IA
	ifNum common.IFIDType
}

type segment struct {
	LoggingID  string
	SegType    proto.PathSegType
	interfaces []asIface
	Updated    time.Time
	Expiry     time.Time
}

func newSegment(res *query.Result) (segment, error) {
	ifs := make([]asIface, 0, len(res.Seg.ASEntries))
	for _, ase := range res.Seg.ASEntries {
		hop, err := ase.HopEntries[0].HopField()
		if err != nil {
			return segment{}, err
		}
		if hop.ConsIngress > 0 {
			iface := asIface{
				IA:    ase.IA(),
				ifNum: hop.ConsIngress,
			}
			ifs = append(ifs, iface)
		}
		if hop.ConsEgress > 0 {
			iface := asIface{
				IA:    ase.IA(),
				ifNum: hop.ConsEgress,
			}
			ifs = append(ifs, iface)
		}
	}
	return segment{
		LoggingID:  res.Seg.GetLoggingID(),
		SegType:    res.Type,
		Updated:    res.LastUpdate,
		Expiry:     res.Seg.MinExpiry(),
		interfaces: ifs,
	}, nil
}

func (s segment) toString(showTimestamps bool) string {
	str := fmt.Sprintf("%s %4s %s", s.LoggingID, s.SegType, ifsArrayToString(s.interfaces))
	if showTimestamps {
		now := time.Now()
		updatedStr := now.Sub(s.Updated).String()
		expiryStr := s.Expiry.Sub(now).String()
		str += fmt.Sprintf(" | Updated: %s Expires in: %s", updatedStr, expiryStr)
	}
	return str
}

func ifsArrayToString(ifs []asIface) string {
	if len(ifs) == 0 {
		return ""
	}
	strs := []string{fmt.Sprintf("%s %4d", ifs[0].IA, ifs[0].ifNum)}
	for i := 1; i < len(ifs)-1; i += 2 {
		strs = append(strs, fmt.Sprintf("%4d %s %4d", ifs[i].ifNum, ifs[i].IA, ifs[i+1].ifNum))
	}
	strs = append(strs, fmt.Sprintf("%4d %s", ifs[len(ifs)-1].ifNum, ifs[len(ifs)-1].IA))
	return strings.Join(strs, ">")
}

// lessThan returns if this segment is < the other segment. It uses the segment type,
// then the number of interfaces and then finally the ID of the interfaces to sort.
func (s *segment) lessThan(o *segment) bool {
	segsLessThan := func(lhs, rhs *segment) bool {
		for i := 0; i < len(lhs.interfaces); i++ {
			if lhs.interfaces[i].IA != rhs.interfaces[i].IA {
				return lhs.interfaces[i].IA.IAInt() < rhs.interfaces[i].IA.IAInt()
			} else if lhs.interfaces[i].ifNum != rhs.interfaces[i].ifNum {
				return lhs.interfaces[i].ifNum < rhs.interfaces[i].ifNum
			}
		}
		return false
	}
	switch {
	case s.SegType != o.SegType:
		// reversed Type comparison so core < down < up
		return s.SegType > o.SegType
	case len(s.interfaces) == 0 || len(o.interfaces) == 0:
		return len(s.interfaces) < len(o.interfaces)
	case s.interfaces[0].IA.IAInt() != o.interfaces[0].IA.IAInt():
		return s.interfaces[0].IA.IAInt() < o.interfaces[0].IA.IAInt()
	case s.interfaces[len(s.interfaces)-1].IA.IAInt() !=
		o.interfaces[len(o.interfaces)-1].IA.IAInt():
		return s.interfaces[len(s.interfaces)-1].IA.IAInt() <
			o.interfaces[len(o.interfaces)-1].IA.IAInt()
	case len(s.interfaces) != len(o.interfaces):
		return len(s.interfaces) < len(o.interfaces)
	default:
		return segsLessThan(s, o)
	}
}

func defaultDBfilename() (string, error) {
	searchPath := "/etc/scion/gen-cache/"
	glob := filepath.Join(searchPath, "ps*path.db")
	filenames, err := filepath.Glob(glob)
	if err != nil {
		return "", fmt.Errorf("Error while listing files: %v", err)
	}
	if len(filenames) == 1 {
		return filenames[0], nil
	}
	reason := "no"
	if len(filenames) > 1 {
		reason = "more than one"
	}
	return "", fmt.Errorf("Found %s files matching '%s'. "+
		"Please specify the path to a DB file using the -db flag.", reason, glob)
}
