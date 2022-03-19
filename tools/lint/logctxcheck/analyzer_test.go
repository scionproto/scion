package logctxcheck_test

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/scionproto/scion/tools/lint/logctxcheck"
)

func Test(t *testing.T) {
	if strings.HasSuffix(os.Getenv("TEST_TARGET"), "go_default_test") {
		t.Skip("Bazel test not supported: https://github.com/bazelbuild/rules_go/issues/2370")
	}
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, logctxcheck.Analyzer, "fail")
}

func TestNamed(t *testing.T) {
	if strings.HasSuffix(os.Getenv("TEST_TARGET"), "go_default_test") {
		t.Skip("Bazel test not supported: https://github.com/bazelbuild/rules_go/issues/2370")
	}
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, logctxcheck.Analyzer, "named")
}
