package mgmtapi

import "time"

func (s *Server) SetNowProvider(nowProvider func() time.Time) {
	s.nowProvider = nowProvider
}
