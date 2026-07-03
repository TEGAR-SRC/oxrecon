package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Format int

const (
	FormatJSON  Format = iota
	FormatYAML
	FormatXML
	FormatCSV
	FormatText
)

func ParseFormat(s string) Format {
	switch s {
	case "json":
		return FormatJSON
	case "yaml", "yml":
		return FormatYAML
	case "xml":
		return FormatXML
	case "csv":
		return FormatCSV
	default:
		return FormatText
	}
}

type Formatter struct {
	Format Format
	Writer *os.File
}

func NewFormatter(format Format, path string) (*Formatter, error) {
	w := os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		w = f
	}
	return &Formatter{Format: format, Writer: w}, nil
}

func (f *Formatter) Write(data any) error {
	switch f.Format {
	case FormatJSON:
		return f.writeJSON(data)
	case FormatYAML:
		return f.writeYAML(data)
	case FormatXML:
		return f.writeXML(data)
	case FormatCSV:
		return f.writeCSV(data)
	default:
		return f.writeText(data)
	}
}

func (f *Formatter) writeJSON(data any) error {
	enc := json.NewEncoder(f.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (f *Formatter) writeYAML(data any) error {
	enc := yaml.NewEncoder(f.Writer)
	enc.SetIndent(2)
	return enc.Encode(data)
}

func (f *Formatter) writeXML(data any) error {
	enc := xml.NewEncoder(f.Writer)
	enc.Indent("", "  ")
	_, err := fmt.Fprintf(f.Writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	if err != nil {
		return err
	}
	return enc.Encode(data)
}

func (f *Formatter) writeCSV(data any) error {
	w := csv.NewWriter(f.Writer)
	defer w.Flush()

	switch d := data.(type) {
	case []string:
		return w.Write(d)
	case [][]string:
		return w.WriteAll(d)
	case map[string]string:
		var records [][]string
		for k, v := range d {
			records = append(records, []string{k, v})
		}
		return w.WriteAll(records)
	default:
		str := fmt.Sprintf("%v", data)
		return w.Write([]string{str})
	}
}

func (f *Formatter) writeText(data any) error {
	switch d := data.(type) {
	case string:
		_, err := fmt.Fprintln(f.Writer, d)
		return err
	case []byte:
		_, err := fmt.Fprintln(f.Writer, string(d))
		return err
	default:
		_, err := fmt.Fprintf(f.Writer, "%+v\n", data)
		return err
	}
}

func (f *Formatter) Close() error {
	if f.Writer != os.Stdout {
		return f.Writer.Close()
	}
	return nil
}

func (f *Formatter) Name() string {
	switch f.Format {
	case FormatJSON:
		return "json"
	case FormatYAML:
		return "yaml"
	case FormatXML:
		return "xml"
	case FormatCSV:
		return "csv"
	default:
		return "text"
	}
}
