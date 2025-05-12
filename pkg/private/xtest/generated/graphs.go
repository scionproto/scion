package generated

import (
	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/pkg/private/xtest/graph"
)

func NewDefaultGraph(ctrl *gomock.Controller) *graph.Graph {
	return graph.NewFromDescription(ctrl, DefaultGraphDescription)
}
