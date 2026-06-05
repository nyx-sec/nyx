// Phase 05 (Track J.3) — Go XXE benign fixture.
//
// Same parser surface as `vuln.go` but `Strict` is left at the
// default `true`, so the doctype is rejected and no entity body is
// substituted.
package benign

import (
	"bytes"
	"encoding/xml"
)

type Data struct {
	XMLName xml.Name `xml:"data"`
	Value   string   `xml:",chardata"`
}

func Run(body string) (*Data, error) {
	d := xml.NewDecoder(bytes.NewReader([]byte(body)))
	out := &Data{}
	if err := d.Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}
