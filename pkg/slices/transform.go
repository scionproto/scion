package slices

func Transform[In any, Out any](in []In, transform func(In) Out) []Out {
	if in == nil {
		return nil
	}
	out := make([]Out, 0, len(in))
	for _, v := range in {
		out = append(out, transform(v))
	}
	return out
}
