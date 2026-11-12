// Copyright 2026 SCION Association
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

package control

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/path/pathpol"
)

const maxSessionPolicyID = math.MaxUint8

// trafficPolicyFile is the JSON format of the traffic policy file. The named maps stay raw, so
// that the parser can find duplicate names.
type trafficPolicyFile struct {
	ConfigVersion  uint64
	TrafficClasses json.RawMessage
	PathPolicies   json.RawMessage
	ASes           asesJSON
}

// asesJSON holds each value of the ASes key in file order.
type asesJSON []json.RawMessage

func (a *asesJSON) UnmarshalJSON(raw []byte) error {
	*a = append(*a, slices.Clone(raw))
	return nil
}

// asEntryJSON is the JSON format of one AS entry. An entry without SessionPolicies is a legacy
// entry.
type asEntryJSON struct {
	Nets            []string
	PathCount       int
	SessionPolicies json.RawMessage
}

var (
	fileKeys    = []string{"ConfigVersion", "TrafficClasses", "PathPolicies", "ASes"}
	asEntryKeys = []string{"Nets", "PathCount", "SessionPolicies"}
)

// sessionPolicyJSON is the JSON format of one session policy. Description is free text for the
// operator, and the parser ignores it.
type sessionPolicyJSON struct {
	ID                *int
	Name              string
	Description       string
	TrafficClass      *string
	PathPolicy        *string
	PerformancePolicy *string
	PathCount         *int
}

var sessionPolicyOnlyKeys = []string{"TrafficClass", "PathPolicy", "PerformancePolicy"}

// trafficPolicyWarning describes a problem in the file that the parser accepts.
type trafficPolicyWarning struct {
	// IA is nil for a warning about the file.
	IA *addr.IA
	// PolicyID is nil for a warning about the file or about an AS entry.
	PolicyID   *int
	PolicyName string
	// Severe is true when the SIG drops traffic or ignores a value that the operator sets.
	Severe bool
	Msg    string
}

func fileWarning(severe bool, msg string) trafficPolicyWarning {
	return trafficPolicyWarning{Severe: severe, Msg: msg}
}

func asWarning(ia addr.IA, severe bool, msg string) trafficPolicyWarning {
	return trafficPolicyWarning{IA: &ia, Severe: severe, Msg: msg}
}

func policyWarning(sp SessionPolicy, severe bool, msg string) trafficPolicyWarning {
	return trafficPolicyWarning{IA: &sp.IA, PolicyID: &sp.ID, PolicyName: sp.Name,
		Severe: severe, Msg: msg}
}

func unknownKeyMsg(key string) string {
	return "unknown key ignored: " + key
}

func duplicateKeyMsg(key string) string {
	return "duplicate key, the parser uses only one value: " + key
}

// parseTrafficPolicy parses the traffic policy file and sorts the result by IA. The session
// policies of one IA keep their file order.
func parseTrafficPolicy(raw []byte) (SessionPolicies, []trafficPolicyWarning, error) {
	if isNull(raw) {
		return nil, nil, serrors.New("traffic policy file must be an object, not null")
	}
	var cfg trafficPolicyFile
	keys, err := decodeObject(raw, &cfg)
	if err != nil {
		return nil, nil, wrapJSONError(raw, err)
	}
	unknown := unknownKeys(keys, fileKeys...)
	warnings, err := topLevelKeyWarnings(keys, unknown)
	if err != nil {
		return nil, warnings, err
	}
	// A null ASes value discards the AS entries of the earlier ASes values. A later value can
	// add entries again, so only a null last value leaves the file without AS entries.
	if len(cfg.ASes) > 0 && isNull(cfg.ASes[len(cfg.ASes)-1]) {
		return nil, warnings, serrors.New(
			"ASes must not be null, omit it for a file without ASes")
	}

	classes, err := decodeNamedMap[*string](cfg.TrafficClasses, "TrafficClasses")
	if err != nil {
		return nil, warnings, err
	}
	if err := checkTrafficClasses(classes); err != nil {
		return nil, warnings, err
	}
	rawPathPolicies, err := decodeNamedMap[json.RawMessage](cfg.PathPolicies, "PathPolicies")
	if err != nil {
		return nil, warnings, err
	}
	pathPolicies, err := resolvePathPolicies(rawPathPolicies)
	if err != nil {
		return nil, warnings, err
	}

	ases, asesWarnings, err := decodeASes(cfg.ASes)
	warnings = append(warnings, asesWarnings...)
	if err != nil {
		return nil, warnings, err
	}
	// A file without AS entries removes all sessions. An unknown key is probably a typo of ASes.
	if len(ases) == 0 {
		if len(unknown) > 0 {
			return nil, warnings, serrors.New(
				"file has no AS entries, but it has unknown keys",
				"unknown", strings.Join(unknown, ", "))
		}
		warnings = append(warnings, fileWarning(true,
			"file has no AS entries, so it gives no session policies"))
	}
	result := make(SessionPolicies, 0, len(ases))
	for _, ia := range slices.Sorted(maps.Keys(ases)) {
		asPolicies, asWarnings, err := parseASEntry(ia, ases[ia], pathPolicies)
		warnings = append(warnings, asWarnings...)
		if err != nil {
			return nil, warnings, err
		}
		result = append(result, asPolicies...)
	}
	return result, warnings, nil
}

// topLevelKeyWarnings returns the warnings for the unknown and duplicate top-level keys. It also
// returns an error for a duplicate named map, but only after it finds all the warnings.
func topLevelKeyWarnings(keys, unknown []string) ([]trafficPolicyWarning, error) {
	var warnings []trafficPolicyWarning
	for _, key := range unknown {
		warnings = append(warnings, fileWarning(true, unknownKeyMsg(key)))
	}
	var dupErr error
	for _, key := range duplicateKeys(keys, strings.EqualFold) {
		switch {
		case containsFold([]string{"TrafficClasses", "PathPolicies"}, key):
			// No legacy file has these keys, so a duplicate is an error. A duplicate legacy
			// key gives only a warning, so that an existing file still loads.
			if dupErr == nil {
				dupErr = serrors.New("duplicate top-level key", "key", key)
			}
		case strings.EqualFold(key, "ASes"):
			warnings = append(warnings, fileWarning(false,
				"duplicate key, the parser merges the AS entries of each value: "+key))
		default:
			warnings = append(warnings, fileWarning(true, duplicateKeyMsg(key)))
		}
	}
	return warnings, dupErr
}

// decodeNamedMap decodes the value of the top-level key into a map. The names are
// case-sensitive.
func decodeNamedMap[V any](raw json.RawMessage, key string) (map[string]V, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if isNull(raw) {
		return nil, serrors.New("value must not be null, omit the key", "key", key)
	}
	var named map[string]V
	keys, err := decodeObject(raw, &named)
	if err != nil {
		return nil, serrors.Wrap("parsing JSON", err, "key", key)
	}
	if dups := duplicateKeys(keys, func(a, b string) bool { return a == b }); len(dups) > 0 {
		return nil, serrors.New("duplicate name", "key", key, "name", dups[0])
	}
	return named, nil
}

// decodeASes decodes the values of the ASes key in file order into one map, as encoding/json
// does for a map field. Each value adds its AS entries, and a later entry for the same IA
// replaces the earlier entry. A null value discards the earlier entries. Two entries for one IA
// give a warning, or an error if one has SessionPolicies.
func decodeASes(values []json.RawMessage,
) (map[addr.IA]json.RawMessage, []trafficPolicyWarning, error) {
	var ases map[addr.IA]json.RawMessage
	entries := make(map[addr.IA][]json.RawMessage)
	var warnings []trafficPolicyWarning
	for _, raw := range values {
		// A null value discards the AS entries of the earlier values. The json.Unmarshal call
		// below sets ases to nil, so clear entries too.
		if isNull(raw) {
			if len(entries) > 0 {
				discarded := make([]string, 0, len(entries))
				for _, ia := range slices.Sorted(maps.Keys(entries)) {
					discarded = append(discarded, ia.String())
				}
				warnings = append(warnings, fileWarning(true, "null ASes value, "+
					"the parser discards the earlier AS entries: "+strings.Join(discarded, ", ")))
			}
			clear(entries)
		}
		// Examine the keys before json.Unmarshal, so that the error for an invalid key gives the
		// key. Two different texts can give the same IA, so group the entries by the parsed IA.
		var iaErr error
		err := walkObject(raw, func(key string, entry json.RawMessage) {
			ia, err := addr.ParseIA(key)
			if err != nil {
				if iaErr == nil {
					iaErr = serrors.Wrap("parsing ISD-AS", err, "key", "ASes", "isd_as", key)
				}
				return
			}
			entries[ia] = append(entries[ia], entry)
		})
		if err != nil {
			return nil, warnings, serrors.Wrap("parsing JSON", err, "key", "ASes")
		}
		if iaErr != nil {
			return nil, warnings, iaErr
		}
		// json.Unmarshal gives the merged map. It also rejects a value that is not an object,
		// because walkObject ignores such a value.
		if err := json.Unmarshal(raw, &ases); err != nil {
			return nil, warnings, serrors.Wrap("parsing JSON", err, "key", "ASes")
		}
	}
	for _, ia := range slices.Sorted(maps.Keys(entries)) {
		if len(entries[ia]) < 2 {
			continue
		}
		for _, entry := range entries[ia] {
			keys, err := objectKeys(entry)
			if err != nil {
				return nil, warnings, serrors.Wrap("parsing AS entry", err, "isd_as", ia)
			}
			if containsFold(keys, "SessionPolicies") {
				return nil, warnings, serrors.New("duplicate AS entry with SessionPolicies",
					"isd_as", ia)
			}
		}
		warnings = append(warnings,
			asWarning(ia, true, "duplicate AS entry, only the last entry applies"))
	}
	return ases, warnings, nil
}

func parseASEntry(ia addr.IA, raw json.RawMessage,
	pathPolicies map[string]*pathpol.Policy) (SessionPolicies, []trafficPolicyWarning, error) {

	var warnings []trafficPolicyWarning
	if ia.IsWildcard() {
		warnings = append(warnings, asWarning(ia, true,
			"AS entry has a wildcard ISD-AS, but an AS entry must name one remote AS"))
	}
	// A legacy file can contain a null entry, so a null entry is valid.
	if isNull(raw) {
		warnings = append(warnings, asWarning(ia, false,
			"AS entry is null, it gives one session policy without prefixes"))
	}
	var entry asEntryJSON
	keys, err := decodeObject(raw, &entry)
	if err != nil {
		return nil, warnings, serrors.Wrap("parsing AS entry", err, "isd_as", ia)
	}
	for _, key := range unknownKeys(keys, asEntryKeys...) {
		switch {
		case strings.Contains(strings.ToLower(key), "session"):
			warnings = append(warnings, asWarning(ia, true,
				"key ignored, the key for session policies is SessionPolicies: "+key))
		case !containsFold(sessionPolicyOnlyKeys, key):
			warnings = append(warnings, asWarning(ia, true, unknownKeyMsg(key)))
		case entry.SessionPolicies != nil:
			// No legacy file has SessionPolicies, so the key is an error.
			return nil, warnings, serrors.New(
				"key must be set on a session policy, not on the AS", "key", key, "isd_as", ia)
		default:
			// A legacy file can contain the key, so it gives only a warning.
			warnings = append(warnings, asWarning(ia, true,
				"key ignored, it is valid only on a session policy: "+key))
		}
	}
	for _, key := range duplicateKeys(keys, strings.EqualFold) {
		if strings.EqualFold(key, "SessionPolicies") {
			return nil, warnings, serrors.New("duplicate SessionPolicies key", "isd_as", ia)
		}
		warnings = append(warnings, asWarning(ia, true, duplicateKeyMsg(key)))
	}
	prefixes, err := parsePrefixes(entry.Nets)
	if err != nil {
		return nil, warnings, serrors.Wrap("parsing AS entry", err, "isd_as", ia)
	}

	if entry.SessionPolicies == nil {
		sp, err := legacySessionPolicy(ia, entry.PathCount, prefixes)
		if err != nil {
			return nil, warnings, err
		}
		return SessionPolicies{sp}, warnings, nil
	}
	result, err := parseSessionPolicies(ia, keys, entry.SessionPolicies, prefixes,
		pathPolicies)
	if err != nil {
		return nil, warnings, err
	}
	warnings = append(warnings, sessionPolicyOrderWarnings(ia, result)...)
	return result, warnings, nil
}

func parseSessionPolicies(ia addr.IA, entryKeys []string, raw json.RawMessage,
	prefixes []*net.IPNet, pathPolicies map[string]*pathpol.Policy) (SessionPolicies, error) {

	if isNull(raw) {
		return nil, serrors.New(
			"SessionPolicies must not be null, omit it for a single session policy",
			"isd_as", ia)
	}
	var rawPolicies []json.RawMessage
	if err := json.Unmarshal(raw, &rawPolicies); err != nil {
		return nil, serrors.Wrap("parsing AS entry", err, "isd_as", ia)
	}
	if len(rawPolicies) == 0 {
		return nil, serrors.New(
			"SessionPolicies must not be empty, omit it for a single session policy",
			"isd_as", ia)
	}
	// A null PathCount leaves asEntryJSON.PathCount at 0, so check the keys.
	if containsFold(entryKeys, "PathCount") {
		return nil, serrors.New(
			"PathCount must be set on each session policy, not on the AS", "isd_as", ia)
	}
	result := make(SessionPolicies, 0, len(rawPolicies))
	seen := make(map[int]struct{}, len(rawPolicies))
	for i, rawPolicy := range rawPolicies {
		s, err := decodeSessionPolicy(rawPolicy)
		if err != nil {
			return nil, serrors.Wrap("parsing session policy", err, "isd_as", ia, "index", i)
		}
		id := *s.ID
		if _, ok := seen[id]; ok {
			return nil, serrors.New("duplicate session policy ID",
				"isd_as", ia, "index", i, "id", id)
		}
		seen[id] = struct{}{}
		sp, err := buildSessionPolicy(ia, prefixes, s, pathPolicies)
		if err != nil {
			return nil, serrors.Wrap("parsing session policy", err,
				"isd_as", ia, "index", i, "id", id)
		}
		result = append(result, sp)
	}
	if !slices.ContainsFunc(result, func(sp SessionPolicy) bool {
		return sp.TrafficMatcher != pktcls.CondFalse
	}) {
		return nil, serrors.New(
			"no session policy can match a packet, because each traffic class is false",
			"isd_as", ia)
	}
	return result, nil
}

// sessionPolicyOrderWarnings reports the session policies that the SIG never uses, and an AS
// without a catch-all. After the first catch-all, the SIG uses a session policy only as a
// failover for the catch-all or for an earlier session policy with the same class text.
func sessionPolicyOrderWarnings(ia addr.IA,
	sessionPolicies SessionPolicies) []trafficPolicyWarning {

	var warnings []trafficPolicyWarning
	for _, sp := range sessionPolicies {
		if sp.TrafficMatcher == pktcls.CondFalse {
			warnings = append(warnings, policyWarning(sp, true,
				"the SIG never uses this session policy, because its traffic class is false"))
		}
	}
	catchAll := slices.IndexFunc(sessionPolicies, func(sp SessionPolicy) bool {
		return sp.TrafficMatcher == pktcls.CondTrue
	})
	if catchAll < 0 {
		return append(warnings, asWarning(ia, true, "no session policy matches all packets, "+
			"the SIG drops a packet that matches no session policy"))
	}
	classes := make(map[string]struct{}, catchAll+1)
	for _, sp := range sessionPolicies[:catchAll+1] {
		classes[sp.TrafficMatcher.String()] = struct{}{}
	}
	for _, sp := range sessionPolicies[catchAll+1:] {
		// The first loop already reports a session policy with a false class. Skip it here,
		// so that the parser gives only one warning for it.
		if sp.TrafficMatcher == pktcls.CondFalse {
			continue
		}
		if _, ok := classes[sp.TrafficMatcher.String()]; !ok {
			warnings = append(warnings, policyWarning(sp, true,
				"the SIG never uses this session policy, because session policy "+
					strconv.Itoa(sessionPolicies[catchAll].ID)+" before it matches all packets"))
		}
	}
	return warnings
}

func legacySessionPolicy(ia addr.IA, pathCount int,
	prefixes []*net.IPNet) (SessionPolicy, error) {

	if pathCount < 0 {
		return SessionPolicy{}, serrors.New("PathCount must not be negative",
			"isd_as", ia, "path_count", pathCount)
	}
	return SessionPolicy{
		ID:             0,
		IA:             ia,
		TrafficMatcher: pktcls.CondTrue,
		PerfPolicy:     DefaultPerfPolicy,
		PathPolicy:     DefaultPathPolicy,
		PathCount:      cmp.Or(pathCount, DefaultPathCount),
		Prefixes:       prefixes,
	}, nil
}

func decodeSessionPolicy(raw json.RawMessage) (sessionPolicyJSON, error) {
	if isNull(raw) {
		return sessionPolicyJSON{}, serrors.New("session policy must not be null")
	}
	if err := checkKeys(raw); err != nil {
		return sessionPolicyJSON{}, err
	}
	var s sessionPolicyJSON
	if err := decodeStrict(raw, &s); err != nil {
		return sessionPolicyJSON{}, serrors.Wrap("parsing JSON", err)
	}
	if s.ID == nil {
		return sessionPolicyJSON{}, serrors.New("ID must be set")
	}
	if *s.ID < 0 || *s.ID > maxSessionPolicyID {
		return sessionPolicyJSON{}, serrors.New("ID out of range",
			"id", *s.ID, "min", 0, "max", maxSessionPolicyID)
	}
	optional := []struct {
		key   string
		value *string
	}{
		{"TrafficClass", s.TrafficClass},
		{"PathPolicy", s.PathPolicy},
		{"PerformancePolicy", s.PerformancePolicy},
	}
	for _, o := range optional {
		if o.value != nil && *o.value == "" {
			return sessionPolicyJSON{}, serrors.New(
				"value must not be empty, omit the key for the default", "key", o.key)
		}
	}
	return s, nil
}

// buildSessionPolicy creates the session policy for ia from s. The caller validates s.ID.
func buildSessionPolicy(ia addr.IA, prefixes []*net.IPNet, s sessionPolicyJSON,
	pathPolicies map[string]*pathpol.Policy) (SessionPolicy, error) {

	var err error
	var matcher pktcls.Cond = pktcls.CondTrue
	if s.TrafficClass != nil {
		if matcher, err = parseTrafficMatcher(*s.TrafficClass); err != nil {
			return SessionPolicy{}, err
		}
	}
	var pathPolicy policies.PathPolicy = DefaultPathPolicy
	if s.PathPolicy != nil {
		if pathPolicy, err = lookupPathPolicy(*s.PathPolicy, pathPolicies); err != nil {
			return SessionPolicy{}, err
		}
	}
	var perfPolicy policies.PerfPolicy = DefaultPerfPolicy
	if s.PerformancePolicy != nil {
		if perfPolicy, err = parsePerfPolicy(*s.PerformancePolicy); err != nil {
			return SessionPolicy{}, err
		}
	}
	pathCount := DefaultPathCount
	if s.PathCount != nil {
		if *s.PathCount < 1 {
			return SessionPolicy{}, serrors.New("PathCount must be 1 or more",
				"path_count", *s.PathCount)
		}
		pathCount = *s.PathCount
	}
	return SessionPolicy{
		IA:             ia,
		ID:             *s.ID,
		Name:           s.Name,
		TrafficMatcher: matcher,
		PerfPolicy:     perfPolicy,
		PathPolicy:     pathPolicy,
		PathCount:      pathCount,
		Prefixes:       copyPrefixes(prefixes),
	}, nil
}

func parseTrafficMatcher(class string) (pktcls.Cond, error) {
	cond, err := pktcls.BuildClassTree(class)
	if err != nil {
		return nil, serrors.Wrap("parsing TrafficClass", err, "class", class)
	}
	// CondClass.Eval always returns false, so a class reference silently matches the wrong
	// packets.
	// TODO: remove this gate as part of https://github.com/scionproto/scion/issues/4971
	if hasClassRef(cond) {
		return nil, serrors.New("class references (cls=) are not supported yet",
			"class", class)
	}
	return cond, nil
}

// hasClassRef reports whether c contains a class reference. BuildClassTree gives the conditions
// of the switch cases as values, not as pointers.
func hasClassRef(c pktcls.Cond) bool {
	switch c := c.(type) {
	case pktcls.CondClass:
		return true
	case pktcls.CondAnyOf:
		return slices.ContainsFunc(c, hasClassRef)
	case pktcls.CondAllOf:
		return slices.ContainsFunc(c, hasClassRef)
	case pktcls.CondNot:
		return hasClassRef(c.Operand)
	}
	return false
}

func lookupPathPolicy(name string,
	pathPolicies map[string]*pathpol.Policy) (policies.PathPolicy, error) {

	if _, ok := pathPolicies[name]; !ok {
		return nil, serrors.New("unknown PathPolicy", "path_policy", name)
	}
	// On each load, SessionPolicy.Copy panics if a JSON round trip of the path policy fails.
	// TODO: remove this gate as part of https://github.com/scionproto/scion/issues/4972
	return nil, serrors.New("named path policies are not supported yet", "path_policy", name)
}

func parsePerfPolicy(name string) (policies.PerfPolicy, error) {
	switch name {
	case "shortest_path":
		// The path selector itself prefers the shorter paths.
		return DefaultPerfPolicy, nil
	case "latency", "jitter", "droprate":
		// The path selector does not call the performance policy yet.
		// TODO: remove this gate as part of https://github.com/scionproto/scion/issues/4974
		// and give shortest_path a performance policy that sorts the paths by length.
		return nil, serrors.New("PerformancePolicy is not supported yet",
			"performance_policy", name)
	}
	return nil, serrors.New("unknown PerformancePolicy", "performance_policy", name,
		"valid", "shortest_path, latency, jitter, droprate")
}

func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

func containsFold(list []string, key string) bool {
	return slices.ContainsFunc(list, func(k string) bool { return strings.EqualFold(k, key) })
}

func wrapJSONError(raw []byte, err error) error {
	var offset int64
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr):
		offset = syntaxErr.Offset
	case errors.As(err, &typeErr):
		offset = typeErr.Offset
	default:
		return serrors.Wrap("parsing JSON", err)
	}
	// The offset counts the bad byte, so before holds the bytes in front of it.
	before := raw[:max(0, min(int(offset)-1, len(raw)))]
	line := bytes.Count(before, []byte("\n")) + 1
	column := len(before) - bytes.LastIndexByte(before, '\n')
	return serrors.Wrap("parsing JSON", err, "line", line, "column", column)
}

func decodeObject(raw json.RawMessage, out any) ([]string, error) {
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return objectKeys(raw)
}

func decodeStrict(raw json.RawMessage, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// checkKeys returns an error for a duplicate key or a null value in the JSON object raw.
func checkKeys(raw json.RawMessage) error {
	var keys, nullKeys []string
	err := walkObject(raw, func(key string, value json.RawMessage) {
		keys = append(keys, key)
		if isNull(value) {
			nullKeys = append(nullKeys, key)
		}
	})
	if err != nil {
		return serrors.Wrap("parsing JSON", err)
	}
	if dups := duplicateKeys(keys, strings.EqualFold); len(dups) > 0 {
		return serrors.New("duplicate key", "key", dups[0])
	}
	if len(nullKeys) > 0 {
		return serrors.New("value must not be null, omit the key", "key", nullKeys[0])
	}
	return nil
}

func walkObject(raw json.RawMessage, fn func(key string, value json.RawMessage)) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return nil
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return serrors.New("object key is not a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		fn(key, value)
	}
	return nil
}

func objectKeys(raw json.RawMessage) ([]string, error) {
	var keys []string
	err := walkObject(raw, func(key string, _ json.RawMessage) { keys = append(keys, key) })
	return keys, err
}

func unknownKeys(keys []string, known ...string) []string {
	var unknown []string
	for _, key := range keys {
		if !containsFold(known, key) {
			unknown = append(unknown, key)
		}
	}
	slices.Sort(unknown)
	return slices.Compact(unknown)
}

func duplicateKeys(keys []string, equal func(a, b string) bool) []string {
	var dups []string
	for i, key := range keys {
		same := func(k string) bool { return equal(k, key) }
		if slices.ContainsFunc(keys[:i], same) && !slices.ContainsFunc(dups, same) {
			dups = append(dups, key)
		}
	}
	slices.Sort(dups)
	return dups
}

var trafficClassName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

func checkTrafficClasses(classes map[string]*string) error {
	for _, name := range slices.Sorted(maps.Keys(classes)) {
		class := classes[name]
		if !trafficClassName.MatchString(name) {
			return serrors.New("invalid traffic class name",
				"traffic_class", name, "pattern", trafficClassName.String())
		}
		if class == nil {
			return serrors.New("traffic class must not be null", "traffic_class", name)
		}
		if *class == "" {
			return serrors.New("traffic class must not be empty", "traffic_class", name)
		}
		if _, err := parseTrafficMatcher(*class); err != nil {
			return serrors.Wrap("parsing traffic class", err, "traffic_class", name)
		}
	}
	return nil
}

func resolvePathPolicies(raw map[string]json.RawMessage) (map[string]*pathpol.Policy, error) {
	names := slices.Sorted(maps.Keys(raw))
	ext := make(pathpol.PolicyMap, len(raw))
	all := make([]*pathpol.ExtPolicy, 0, len(names))
	for _, name := range names {
		// An empty PathPolicy is an error, so no session policy can select the empty name.
		if name == "" {
			return nil, serrors.New("path policy name must not be empty")
		}
		pol, err := decodePathPolicy(raw[name])
		if err != nil {
			return nil, serrors.Wrap("parsing path policy", err, "path_policy", name)
		}
		pol.Name = name
		ext[name] = pol
		all = append(all, pol)
	}
	// pathpol.PolicyFromExtPolicy recurses without limit on a cycle.
	order, err := extendsOrder(ext, names)
	if err != nil {
		return nil, err
	}
	result := make(map[string]*pathpol.Policy, len(names))
	for _, name := range order {
		pol, err := pathpol.PolicyFromExtPolicy(ext[name], all)
		if err != nil {
			return nil, serrors.Wrap("resolving path policy", err, "path_policy", name)
		}
		// Store the merged policy without the extends list. A policy that extends this one then
		// copies the merged fields and does not resolve the chain again.
		ext[name].Policy, ext[name].Extends = pol, nil
		result[name] = pol
	}
	return result, nil
}

// decodePathPolicy decodes the value of one PathPolicies entry.
func decodePathPolicy(raw json.RawMessage) (*pathpol.ExtPolicy, error) {
	if isNull(raw) {
		return nil, serrors.New("path policy must not be null")
	}
	if err := checkPathPolicyJSON(raw); err != nil {
		return nil, err
	}
	var pol *pathpol.ExtPolicy
	if err := decodeStrict(raw, &pol); err != nil {
		return nil, err
	}
	if pol.Policy == nil {
		pol.Policy = &pathpol.Policy{}
	}
	sortOptions(pol.Policy)
	return pol, nil
}

// checkPathPolicyJSON finds the errors in the JSON of a path policy that the strict decoder does
// not find. With such an error, pathpol matches the wrong paths or panics.
func checkPathPolicyJSON(raw json.RawMessage) error {
	if err := checkKeys(raw); err != nil {
		return err
	}
	values := make(map[string]json.RawMessage)
	err := walkObject(raw, func(key string, value json.RawMessage) {
		values[key] = value
	})
	if err != nil {
		return err
	}
	lookup := func(name string) (json.RawMessage, bool) {
		for key, value := range values {
			if strings.EqualFold(key, name) {
				return value, true
			}
		}
		return nil, false
	}
	if rules, ok := lookup("remote_isd_ases"); ok {
		if err := checkRulesJSON(rules); err != nil {
			return serrors.Wrap("parsing remote_isd_ases", err)
		}
	}
	if seq, ok := lookup("sequence"); ok {
		var s string
		if err := json.Unmarshal(seq, &s); err != nil {
			return serrors.Wrap("parsing sequence", err)
		}
		if s == "" {
			return serrors.New("sequence must not be empty, omit the key")
		}
	}
	if local, ok := lookup("local_isd_ases"); ok {
		if err := checkLocalISDASesJSON(local); err != nil {
			return serrors.Wrap("parsing local_isd_ases", err)
		}
	}
	options, ok := lookup("options")
	if !ok {
		return nil
	}
	var rawOptions []json.RawMessage
	if err := json.Unmarshal(options, &rawOptions); err != nil {
		return serrors.Wrap("parsing options", err)
	}
	for i, rawOption := range rawOptions {
		if err := checkOptionJSON(rawOption); err != nil {
			return serrors.Wrap("parsing option", err, "index", i)
		}
	}
	return nil
}

// checkRulesJSON checks the remote_isd_ases rules. RemoteISDAS.UnmarshalJSON ignores an unknown
// key in a rule, so the function also decodes the rules with the strict decoder.
func checkRulesJSON(raw json.RawMessage) error {
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	if len(rules) == 0 {
		return serrors.New("list must not be empty, an empty list rejects all paths")
	}
	for i, rule := range rules {
		if isNull(rule) {
			return serrors.New("rule must not be null", "index", i)
		}
		if err := checkKeys(rule); err != nil {
			return serrors.Wrap("parsing rule", err, "index", i)
		}
	}
	var r []pathpol.ISDASRule
	if err := decodeStrict(raw, &r); err != nil {
		return err
	}
	// A rule without isd_as gives the ISD-AS 0-0, which matches all ASes.
	for i, rule := range rules {
		keys, err := objectKeys(rule)
		if err != nil {
			return serrors.Wrap("parsing rule", err, "index", i)
		}
		if !containsFold(keys, "isd_as") {
			return serrors.New("rule must have isd_as", "index", i)
		}
	}
	return nil
}

func checkLocalISDASesJSON(raw json.RawMessage) error {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		return serrors.New("list must not be empty, an empty list rejects all paths")
	}
	for i, entry := range entries {
		if isNull(entry) {
			return serrors.New("entry must not be null", "index", i)
		}
	}
	return nil
}

// checkOptionJSON checks one entry in the options list of a path policy. An option without a
// policy causes a panic when pathpol filters paths, because pathpol.Policy.evalOptions then
// calls a method through a nil *ExtPolicy.
func checkOptionJSON(raw json.RawMessage) error {
	if isNull(raw) {
		return serrors.New("option must not be null")
	}
	var option struct {
		Policy json.RawMessage
	}
	keys, err := decodeObject(raw, &option)
	if err != nil {
		return err
	}
	if dups := duplicateKeys(keys, strings.EqualFold); len(dups) > 0 {
		return serrors.New("duplicate key", "key", dups[0])
	}
	if len(option.Policy) == 0 || isNull(option.Policy) {
		return serrors.New("option must have a policy")
	}
	if err := checkKeys(raw); err != nil {
		return err
	}
	policyKeys, err := objectKeys(option.Policy)
	if err != nil {
		return err
	}
	if containsFold(policyKeys, "extends") {
		return serrors.New("option policy must not have extends, pathpol does not resolve it")
	}
	return checkPathPolicyJSON(option.Policy)
}

// sortOptions sorts the options as pathpol.NewPolicy does. Policy.evalOptions requires this order.
func sortOptions(pol *pathpol.Policy) {
	slices.SortStableFunc(pol.Options, func(a, b pathpol.Option) int {
		return cmp.Compare(b.Weight, a.Weight)
	})
	for _, option := range pol.Options {
		if option.Policy != nil && option.Policy.Policy != nil {
			sortOptions(option.Policy.Policy)
		}
	}
}

func extendsOrder(ext pathpol.PolicyMap, names []string) ([]string, error) {
	const (
		visiting = iota + 1
		done
	)
	state := make(map[string]int, len(ext))
	order := make([]string, 0, len(names))
	var visit func(name string, chain []string) error
	visit = func(name string, chain []string) error {
		chain = append(chain, name)
		switch state[name] {
		case done:
			return nil
		case visiting:
			return serrors.New("path policy extends itself",
				"cycle", strings.Join(chain, " -> "))
		}
		pol, ok := ext[name]
		if !ok {
			return nil
		}
		state[name] = visiting
		for _, parent := range pol.Extends {
			if err := visit(parent, chain); err != nil {
				return err
			}
		}
		state[name] = done
		order = append(order, name)
		return nil
	}
	for _, name := range names {
		if err := visit(name, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}
