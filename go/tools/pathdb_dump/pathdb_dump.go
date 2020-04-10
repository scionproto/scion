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
	"database/sql"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
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
	filename := copyDBToTemp(origFilename)
	defer removeAllDir(filepath.Dir(filename))

	// TODO it would be ideal to open the DB file in place instead of copying it, but we always get
	// a "database is locked" error. Tried with a combination of ?mode=ro&_journal=OFF&_mutex=no&
	// _txlock=immediate&journal=wal&_query_only=yes?_locking=normal&immutable=true
	// Fails because setting journal (vendor/.../mattn/.../sqlite3.go:1480), for all journal modes")
	db, err := sql.Open("sqlite3", filename+"?mode=ro")
	if err != nil {
		errorAndQuit(err.Error())
	}
	// TODO: three queries? query 1 and 3 coud be easily joined
	sqlstmt := `SELECT SegRowID, Type from SegTypes`
	rows, err := db.Query(sqlstmt)
	if err != nil {
		errorAndQuit(err.Error())
	}
	var segRowID int64
	var segType proto.PathSegType
	segTypes := map[int64]proto.PathSegType{}
	for rows.Next() {
		err = rows.Scan(&segRowID, &segType)
		if err != nil {
			errorAndQuit(err.Error())
		}
		segTypes[segRowID] = segType
	}
	rows.Close()

	sqlstmt = `SELECT IsdID, AsID, IntfID, SegRowID FROM IntfToSeg`
	rows, err = db.Query(sqlstmt)
	if err != nil {
		errorAndQuit(err.Error())
	}
	var isd addr.ISD
	var as addr.AS
	var ifaceID common.IFIDType
	segInterfaces := map[int64][]asIface{}
	for rows.Next() {
		err = rows.Scan(&isd, &as, &ifaceID, &segRowID)
		if err != nil {
			errorAndQuit(err.Error())
		}
		segInterfaces[segRowID] = append(segInterfaces[segRowID], newASIface(isd, as, ifaceID))
	}
	rows.Close()

	sqlstmt = `SELECT RowID, LastUpdated, Segment, MaxExpiry,
    StartIsdID, StartAsID, EndIsdID, EndAsID FROM Segments`
	rows, err = db.Query(sqlstmt)
	if err != nil {
		errorAndQuit(err.Error())
	}
	var packedSeg []byte
	var lastUpdated, maxExpiry int64
	var startISD, endISD addr.ISD
	var startAS, endAS addr.AS
	segments := []segment{}
	for rows.Next() {
		err = rows.Scan(&segRowID, &lastUpdated, &packedSeg, &maxExpiry,
			&startISD, &startAS, &endISD, &endAS)
		if err != nil {
			errorAndQuit(err.Error())
		}
		segmt := newSegment(segTypes[segRowID], startISD, startAS, endISD, endAS,
			segInterfaces[segRowID], lastUpdated, maxExpiry)
		segments = append(segments, segmt)
	}
	rows.Close()
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

func newASIface(isd addr.ISD, as addr.AS, ifNum common.IFIDType) asIface {
	return asIface{IA: addr.IA{I: isd, A: as}, ifNum: ifNum}
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
	SegType    proto.PathSegType
	Src        addr.IA
	Dst        addr.IA
	interfaces []asIface
	Updated    time.Time
	Expiry     time.Time
}

func newSegment(segType proto.PathSegType, srcI addr.ISD, srcA addr.AS, dstI addr.ISD, dstA addr.AS,
	interfaces []asIface, updateTime, expiryTime int64) segment {

	return segment{SegType: segType, Src: addr.IA{I: srcI, A: srcA}, Dst: addr.IA{I: dstI, A: dstA},
		interfaces: interfaces, Updated: time.Unix(0, updateTime), Expiry: time.Unix(expiryTime, 0)}
}

func (s segment) toString(showTimestamps bool) string {
	toRet := s.SegType.String() + "\t"
	now := time.Now()
	updatedStr := now.Sub(s.Updated).String()
	expiryStr := s.Expiry.Sub(now).String()
	toRet += ifsArrayToString(s.interfaces)
	if showTimestamps {
		toRet += "\tUpdated: " + updatedStr + "\t: Expires in: " + expiryStr
	}
	return toRet
}

func (s segment) String() string {
	return s.toString(true)
}

// returns if this segment is < the other segment. It relies on the
// short circuit of the OR op. E.g. (for two dimensions):
// a.T < b.T || ( a.T == b.T && a.L < b.L )
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
	// reversed Type comparison so core < down < up
	return s.SegType > o.SegType || (s.SegType == o.SegType &&
		(len(s.interfaces) < len(o.interfaces) ||
			(len(s.interfaces) == len(o.interfaces) && (segsLessThan(s, o)))))
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
