package parser

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"

	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	pp "github.com/argonsecurity/pipeline-parser/pkg/handler"
	ppModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string]*ppModels.Pipeline, error) {

	files := make(map[string]*ppModels.Pipeline)
	if err := fs.WalkDir(target, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		parsedPipeline, err := p.ParseFile(ctx, target, path)
		if err != nil {
			// TODO add debug for parse errors
			return nil
		}
		files[path] = parsedPipeline
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

func (p *Parser) ParseFile(ctx context.Context, fs fs.FS, path string) (*ppModels.Pipeline, error) {
	f, err := os.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sourcesMap, ok := ctx.Value("sourcesMap").(map[string]ppConsts.Platform)
	if !ok {
		return nil, errors.New("sourcesMap not found in context")
	}
	platform := sourcesMap[path]

	return p.parse(path, f, platform)
}

func (p *Parser) parse(path string, r io.Reader, platform ppConsts.Platform) (*ppModels.Pipeline, error) {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	parsedFile, err := pp.Handle(content, platform)
	if err != nil {
		return nil, err
	}

	return parsedFile, nil
}
