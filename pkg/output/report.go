package output

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

type ReportBuilder struct {
	buf bytes.Buffer
}

func NewReportBuilder() *ReportBuilder {
	return &ReportBuilder{}
}

func (rb *ReportBuilder) Header(title string) *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf("╔══════════════════════════════════════════════════════╗\n"))
	rb.buf.WriteString(fmt.Sprintf("║  %-52s ║\n", title))
	rb.buf.WriteString(fmt.Sprintf("╚══════════════════════════════════════════════════════╝\n\n"))
	return rb
}

func (rb *ReportBuilder) Section(title string) *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf("━━━ %s ━━━\n", title))
	return rb
}

func (rb *ReportBuilder) Field(key string, value string) *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf("  %-25s %s\n", key+":", value))
	return rb
}

func (rb *ReportBuilder) List(title string, items []string) *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf("%s (%d):\n", title, len(items)))
	for _, item := range items {
		rb.buf.WriteString(fmt.Sprintf("  - %s\n", item))
	}
	return rb
}

func (rb *ReportBuilder) Raw(data string) *ReportBuilder {
	rb.buf.WriteString(data)
	rb.buf.WriteString("\n")
	return rb
}

func (rb *ReportBuilder) Text(format string, args ...any) *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf(format, args...))
	rb.buf.WriteString("\n")
	return rb
}

func (rb *ReportBuilder) Separator() *ReportBuilder {
	rb.buf.WriteString(strings.Repeat("-", 55) + "\n")
	return rb
}

func (rb *ReportBuilder) Footer() *ReportBuilder {
	rb.buf.WriteString(fmt.Sprintf("\nGenerated: %s\n", time.Now().Format(time.RFC3339)))
	rb.buf.WriteString(strings.Repeat("=", 55) + "\n")
	return rb
}

func (rb *ReportBuilder) String() string {
	return rb.buf.String()
}

func (rb *ReportBuilder) Bytes() []byte {
	return rb.buf.Bytes()
}

func (rb *ReportBuilder) WriteToFile(filename string) error {
	return fmt.Errorf("not implemented")
}
