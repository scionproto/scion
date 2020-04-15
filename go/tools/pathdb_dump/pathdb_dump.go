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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathdb/query"
	"github.com/scionproto/scion/go/lib/pathdb/sqlite"
	"github.com/scionproto/scion/go/proto"
)

func main() {
	var origFilename string
	var showTimestamps bool
	flag.StringVar(&origFilename, "db", "", "Sqlite DB file (optional)")
	flag.BoolVar(&showTimestamps, "t", false, "Show update and expiration times")
	flag.Parse()

	if origFilename == "" {
		origFilename = defaultDBfilename()
	}
	// TODO(juagargi) it would be ideal to open the DB file in place instead of copying it,
	// but we always get a "database is locked" error. Tried with a combination of
	// ?mode=ro&_journal=OFF&_mutex=no&_txlock=immediate&journal=wal&_query_only=yes
	// ?_locking=normal&immutable=true . It fails because of setting journal
	// (vendor/.../mattn/.../sqlite3.go:1480), for all journal modes)
	filename := copyDBToTemp(origFilename)
	defer removeAllDir(filepath.Dir(filename))

	db, err := sqlite.New(filename)
	if err != nil {
		errorAndQuit(err.Error())
	}
	defer db.Close()

	ch, err := db.GetAll(context.Background())
	if err != nil {
		errorAndQuit(err.Error())
	}
	var segments []segment
	for res := range ch {
		if res.Err != nil {
			errorAndQuit(err.Error())
		}
		segments = append(segments, newSegment(res.Result))
	}
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].lessThan(&segments[j])
	})
	for _, seg := range segments {
		fmt.Println(seg.toString(showTimestamps))
	}
}

func errorAndQuit(msg string, params ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", params...)
	os.Exit(1)
}

type asIface struct {
	IA    addr.IA
	ifNum common.IFIDType
}

func ifsArrayToString(ifs []asIface) string {
	if len(ifs) == 0 {
		return ""
	}
	strs := []string{fmt.Sprintf("%s %d", ifs[0].IA, ifs[0].ifNum)}
	for i := 1; i < len(ifs)-1; i += 2 {
		strs = append(strs, fmt.Sprintf("%d %s %d", ifs[i].ifNum, ifs[i].IA, ifs[i+1].ifNum))
	}
	strs = append(strs, fmt.Sprintf("%d %s", ifs[len(ifs)-1].ifNum, ifs[len(ifs)-1].IA))
	return strings.Join(strs, ">")
}

type segment struct {
	LoggingID  string
	SegType    proto.PathSegType
	interfaces []asIface
	Updated    time.Time
	Expiry     time.Time
}

func newSegment(res *query.Result) segment {
	ifs := make([]asIface, 0, len(res.Seg.ASEntries))
	for _, ase := range res.Seg.ASEntries {
		hop, err := ase.HopEntries[0].HopField()
		if err != nil {
			errorAndQuit(err.Error())
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
	}
}

func (s segment) toString(showTimestamps bool) string {
	str := fmt.Sprintf("%s\t%s\t%s", s.LoggingID, s.SegType, ifsArrayToString(s.interfaces))
	if showTimestamps {
		now := time.Now()
		updatedStr := now.Sub(s.Updated).String()
		expiryStr := s.Expiry.Sub(now).String()
		str += fmt.Sprintf("\tUpdated: %s\tExpires in: %s", updatedStr, expiryStr)
	}
	return str
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
	case len(s.interfaces) != len(o.interfaces):
		return len(s.interfaces) < len(o.interfaces)
	default:
		return segsLessThan(s, o)
	}
}

func defaultDBfilename() string {
	searchPath := "/etc/scion/gen-cache/"
	glob := filepath.Join(searchPath, "ps*path.db")
	filenames, err := filepath.Glob(glob)
	if err != nil {
		errorAndQuit("Error while listing files: %v", err)
	}
	if len(filenames) == 1 {
		return filenames[0]
	}
	reason := "no"
	if len(filenames) > 1 {
		reason = "more than one"
	}
	errorAndQuit("Found %s files matching '%s'. "+
		"Please specify the path to a DB file using the -db flag.", reason, glob)
	return ""
}

// returns the name of the created file
func copyDBToTemp(filename string) string {
	copyOneFile := func(dstDir, srcFileName string) error {
		src, err := os.Open(srcFileName)
		if err != nil {
			return fmt.Errorf("cannot open %s: %v", srcFileName, err)
		}
		defer src.Close()
		dstFilename := filepath.Join(dstDir, filepath.Base(srcFileName))
		dst, err := os.Create(dstFilename)
		if err != nil {
			return fmt.Errorf("cannot open %s: %v", dstFilename, err)
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		if err != nil {
			return fmt.Errorf("cannot copy %s to %s: %v", srcFileName, dstFilename, err.Error())
		}
		return nil
	}
	dirName, err := ioutil.TempDir("/tmp", "pathserver_dump")
	if err != nil {
		errorAndQuit("Error creating temporary dir: %v", err)
	}

	err = copyOneFile(dirName, filename)
	if err != nil {
		errorAndQuit(err.Error())
	}
	_ = copyOneFile(dirName, filename+"-wal") // Fails when DB not open (i.e. SCION is not running)
	return filepath.Join(dirName, filepath.Base(filename))
}

func removeAllDir(dirName string) {
	err := os.RemoveAll(dirName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error when removing temp dir %s: %v\n", dirName, err)
	}
}
