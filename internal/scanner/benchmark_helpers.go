package scanner

import "os"

func writeFile(path, data string) error {
	return os.WriteFile(path, []byte(data), 0600)
}
