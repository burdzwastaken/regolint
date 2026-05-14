package transformer

import (
	"bytes"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"

	"github.com/burdzwastaken/regolint/internal/model"
)

func (t *Transformer) extractLines(filePath string, file *ast.File) []model.LineInfo {
	tokenFile := t.fset.File(file.Pos())
	if tokenFile == nil {
		return nil
	}

	if content, err := readSourceFile(filePath); err == nil {
		return t.extractLinesFromContent(tokenFile, content)
	}

	return t.extractLinesFromTokenFile(tokenFile)
}

func readSourceFile(filePath string) ([]byte, error) {
	cleanPath := filepath.Clean(filePath)
	root, err := os.OpenRoot(filepath.Dir(cleanPath))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	return root.ReadFile(filepath.Base(cleanPath))
}

func (t *Transformer) extractLinesFromContent(tokenFile interface {
	LineCount() int
	LineStart(int) token.Pos
	Offset(token.Pos) int
}, content []byte) []model.LineInfo {
	lineCount := tokenFile.LineCount()
	lines := make([]model.LineInfo, 0, lineCount)
	for line := 1; line <= lineCount; line++ {
		start := tokenFile.LineStart(line)
		startOffset := tokenFile.Offset(start)

		endOffset := len(content)
		if line < lineCount {
			endOffset = tokenFile.Offset(tokenFile.LineStart(line + 1))
		}

		lineContent := content[startOffset:endOffset]
		lineContent = bytes.TrimSuffix(lineContent, []byte("\n"))
		lineContent = bytes.TrimSuffix(lineContent, []byte("\r"))

		lines = append(lines, model.LineInfo{
			Number:   line,
			Length:   len(lineContent),
			Position: t.position(start),
		})
	}

	return lines
}

func (t *Transformer) extractLinesFromTokenFile(tokenFile interface {
	LineCount() int
	LineStart(int) token.Pos
	Offset(token.Pos) int
	Size() int
}) []model.LineInfo {
	lineCount := tokenFile.LineCount()
	lines := make([]model.LineInfo, 0, lineCount)
	for line := 1; line <= lineCount; line++ {
		start := tokenFile.LineStart(line)
		startOffset := tokenFile.Offset(start)

		endOffset := tokenFile.Size()
		if line < lineCount {
			endOffset = tokenFile.Offset(tokenFile.LineStart(line + 1))
		}

		length := endOffset - startOffset
		if length > 0 && line < lineCount {
			length--
		}

		lines = append(lines, model.LineInfo{
			Number:   line,
			Length:   length,
			Position: t.position(start),
		})
	}

	return lines
}
