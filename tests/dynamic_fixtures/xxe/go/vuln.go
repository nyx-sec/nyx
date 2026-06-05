// Phase 05 (Track J.3) — Go XXE vuln fixture.
//
// The function builds an `encoding/xml.Decoder` against the attacker
// payload with `Strict: false` so the doctype is parsed and any
// `<!ENTITY xxe SYSTEM "file:///…">` in the payload is resolved and
// substituted into element values.
package vuln

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
	d.Strict = false
	out := &Data{}
	if err := d.Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}
