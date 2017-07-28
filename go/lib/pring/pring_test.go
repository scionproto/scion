package pring

import (
	"fmt"
	"testing"
)

func reader(t *testing.T, buffer []byte, expected int, r *PRing) {
	t.Parallel()
	count := 0
	for {
		n, err := r.Read(buffer)
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
		fmt.Printf("Read %v\n", buffer[:n])
		count += n
		if count == expected {
			break
		}
	}
}

func writer(t *testing.T, buffer []byte, pattern []int, r *PRing) {
	t.Parallel()
	for _, v := range pattern {
		r.Write(buffer[:v])
		fmt.Printf("Wrote %v\n", buffer[:v])
	}
}

func TestWrite(t *testing.T) {
	buffer := make([]byte, 256)
	for i := 0; i < 256; i++ {
		buffer[i] = byte(i)
	}

	tests := []struct {
		Name     string
		RingSize int
		BufSize  int
		Pattern  []int
		Expected int
	}{
		{"Test 1", 10, 10, []int{1}, 1},
		{"Test 2", 10, 10, []int{4, 4, 4}, 12},
		{"Test 3", 10, 10, []int{1, 1, 1, 1, 1, 1, 1, 1}, 8},
		{"Test 4", 10, 10, []int{8, 7, 6, 5, 4, 3, 2, 1}, 36},
		{"Test 5", 10, 20, []int{10, 10, 10, 10}, 40},
		{"Test 6", 10, 20, []int{3, 3, 3, 3, 3, 3, 3, 3, 3, 3}, 30},
		{"Test 7", 10, 20, []int{5, 5, 5, 5, 5, 5, 5, 5}, 40},
		{"Test 8", 10, 20, []int{0, 0, 3, 10, 0, 7}, 20},
		{"Test 9", 100, 100, []int{50, 50, 50, 60, 40}, 250},
	}

	for _, test := range tests {
		t.Run(test.Name,
			func(t *testing.T) {
				pr := NewPRing(test.RingSize)
				b := make([]byte, test.BufSize)
				t.Run("writer",
					func(t *testing.T) {
						writer(t, buffer, test.Pattern, pr)
					})
				t.Run("reader",
					func(t *testing.T) {
						reader(t, b, test.Expected, pr)
					})
			})
	}

	/*
		b := NewPRing(10)
		n, err := b.Write([]byte{1, 2, 3, 4, 5})
		if n != 5 {
			t.Errorf("Write: Expected %d, have %d.", 5, n)
		}
		if err != nil {
			t.Errorf("Write: Expected %v, have %v.", nil, err)
		}

		s := make([]byte, 10)
		n, err = b.Read(s)
		if n != 5 {
			t.Errorf("Read: Expected %d, have %d", 5, n)
		}
		if err != nil {
			t.Errorf("Read: Expected %v, have %v", nil, err)
		}
	*/

}
