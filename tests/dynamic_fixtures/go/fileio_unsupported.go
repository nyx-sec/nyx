// File I/O — unsupported fixture.
// Entry is a method on a struct.
// Test sets confidence = Low to get Unsupported(ConfidenceTooLow).
// Entry: FileServer.Serve  Cap: FILE_IO
// Expected verdict: Unsupported

package entry

import (
	"fmt"
	"os"
)

type FileServer struct{ BaseDir string }

func (s *FileServer) Serve(path string) {
	data, err := os.ReadFile(s.BaseDir + "/" + path)
	if err == nil {
		fmt.Print(string(data))
	}
}
