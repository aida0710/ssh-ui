package application

import (
	"errors"

	"ssh-ui/internal/config"
)

var (
	ErrDuplicateDestinationAlias = errors.New("the destination file already declares this alias")
	ErrSameFileMove              = errors.New("source and destination are the same file")
)

// ExtractHostBlock removes the block declaring alias and returns its lines.
//
// The removed range is exactly the range the projection shows as the block's
// raw text: the Host header line through the line before the next Host or Match
// header, including the trailing comments and blank lines the block owns. A
// comment written above a header belongs to the block before it and stays put.
func ExtractHostBlock(file *config.File, alias string) ([]config.Line, error) {
	block, ok := FindHostBlock(file, alias)
	if !ok {
		return nil, ErrHostNotFound
	}
	extracted := make([]config.Line, 0, block.End-block.Header)
	extracted = append(extracted, file.Lines[block.Header:block.End]...)

	remaining := make([]config.Line, 0, len(file.Lines)-len(extracted))
	remaining = append(remaining, file.Lines[:block.Header]...)
	remaining = append(remaining, file.Lines[block.End:]...)
	file.Lines = remaining
	return extracted, nil
}

// AppendHostBlock appends extracted lines to the end of file, separated by one
// blank line when the file does not already end with one. The appended lines
// are never rewritten, so the moved block keeps every byte, including lines the
// engine could not decompose.
func AppendHostBlock(file *config.File, lines []config.Line) {
	if len(lines) == 0 {
		return
	}
	if len(file.Lines) > 0 {
		ending := dominantEnding(file)
		last := &file.Lines[len(file.Lines)-1]
		if last.Ending == "" {
			last.Ending = ending
		}
		if last.Kind != config.LineBlank {
			file.Lines = append(file.Lines, config.Line{Kind: config.LineBlank, Ending: ending})
		}
	}
	file.Lines = append(file.Lines, lines...)
}

// MoveHostBlock moves one host block from source to destination.
//
// The destination is checked first so a refused move leaves both files exactly
// as they were. Both files are composed from the bytes the caller loaded, so
// the source loses only the block's lines and the destination gains exactly
// those lines.
func MoveHostBlock(source, destination *config.File, alias string) ([]config.Line, error) {
	if _, exists := FindHostBlock(destination, alias); exists {
		return nil, ErrDuplicateDestinationAlias
	}
	extracted, err := ExtractHostBlock(source, alias)
	if err != nil {
		return nil, err
	}
	AppendHostBlock(destination, extracted)
	return extracted, nil
}

// movedAliases lists the concrete aliases a moved block declares, so the caller
// can explain the reordering for every alias the move affects. Wildcards and
// negations are skipped because this engine never claims to resolve them.
func movedAliases(lines []config.Line) []string {
	block := &config.File{Lines: lines}
	var aliases []string
	for _, candidate := range block.Blocks() {
		if candidate.Kind != config.BlockHost {
			continue
		}
		for _, pattern := range candidate.Patterns {
			if pattern.Negated || pattern.Wildcard {
				continue
			}
			aliases = append(aliases, pattern.Value)
		}
	}
	return aliases
}
