// Copyright 2023 Anapaya Systems

package command

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var headers = []struct {
	Search  *regexp.Regexp
	Replace string
}{
	{Search: regexp.MustCompile("\\)\\=\n\n## "), Replace: ")=\n\n# "},
	{Search: regexp.MustCompile("\n### "), Replace: "## "},
	{Search: regexp.MustCompile("\n#### "), Replace: "### "},
	{Search: regexp.MustCompile("\n##### "), Replace: "#### "},
}

func NewGendocs(pather Pather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:    "gendocs <directory>",
		Short:  "Generate documentation",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Root().DisableAutoGenTag = true

			directory := args[0]
			if err := os.MkdirAll(directory, 0755); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}

			if err := genMarkdownTree(cmd.Root(), directory); err != nil {
				return fmt.Errorf("generating documentation: %w", err)
			}
			return nil
		},
	}
	return cmd
}

func genMarkdownTree(cmd *cobra.Command, dir string) error {
	var children []string
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := genMarkdownTree(c, dir); err != nil {
			return err
		}
		children = append(children, strings.ReplaceAll(c.CommandPath(), " ", "_"))
	}

	var buf bytes.Buffer
	if _, err := buf.WriteString("---\norphan: true\n---\n\n"); err != nil {
		return err
	}
	fmt.Fprintf(&buf, "(app-%s)=\n\n", strings.Replace(cmd.CommandPath(), " ", "-", -1))
	if err := doc.GenMarkdown(cmd, &buf); err != nil {
		return err
	}

	// Create index.
	if len(children) != 0 {
		if _, err := buf.WriteString("```{toctree}\n---\nhidden: true\n---\n"); err != nil {
			return err
		}
		if _, err := buf.WriteString(strings.Join(children, "\n")); err != nil {
			return err
		}
		if _, err := buf.WriteString("\n```\n"); err != nil {
			return err
		}
	}

	// Replace titles
	raw := buf.Bytes()
	for _, h := range headers {
		raw = h.Search.ReplaceAll(raw, []byte(h.Replace))
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
	return os.WriteFile(filepath.Join(dir, basename), raw, 0666)
}
