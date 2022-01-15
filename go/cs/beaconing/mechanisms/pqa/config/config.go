package pqacfg

import (
	"io/ioutil"

	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	yaml "gopkg.in/yaml.v2"
)

type PqaCfg struct {
	Origination OriginatorCfg `yaml:"originator"`
	Propagation PropagatorCfg `yaml:"propagator"`
}

type TargetIdentifier string

type QualityIdentifier string

var qIdentToQuality = map[QualityIdentifier]pqa_extension.Quality{
	"latency":    pqa_extension.Latency,
	"throughput": pqa_extension.Throughput,
}

// Turns a QualityIdentifier (cfg) into a Quality (extension)
func (q QualityIdentifier) Quality() pqa_extension.Quality {
	return qIdentToQuality[q]
}

func StringToQuality(s string) pqa_extension.Quality {
	return QualityIdentifier(s).Quality()
}

func StringToDirection(s string) pqa_extension.Direction {
	return DirectionIdentifier(s).Direction()
}

type DirectionIdentifier string

var dirIdentToDirection = map[DirectionIdentifier]pqa_extension.Direction{
	"forward":   pqa_extension.Forward,
	"backward":  pqa_extension.Backward,
	"symmetric": pqa_extension.Symmetric,
}

// Turns a DirectionIdentifier (cfg) into a Direction (extension)
func (d DirectionIdentifier) Direction() pqa_extension.Direction {
	return dirIdentToDirection[d]
}

func LoadPqaCfgFromYAML(file string) (*PqaCfg, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var cfg PqaCfg
	err = yaml.Unmarshal(data, &cfg)

	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
