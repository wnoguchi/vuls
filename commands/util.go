/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package commands

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$`)

// JSONDirs is array of json files path.
type jsonDirs []string

// sort as recent directories are at the head
func (d jsonDirs) Len() int {
	return len(d)
}
func (d jsonDirs) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d jsonDirs) Less(i, j int) bool {
	return d[j] < d[i]
}

// getValidJSONDirs return valid json directory as array
// Returned array is sorted so that recent directories are at the head
func lsValidJSONDirs() (dirs jsonDirs, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(c.Conf.ResultsDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", c.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && jsonDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(c.Conf.ResultsDir, d.Name())
			dirs = append(dirs, jsonDir)
		}
	}
	sort.Sort(dirs)
	return
}

// jsonDir returns
// If there is an arg, check if it is a valid format and return the corresponding path under results.
// If passed via PIPE (such as history subcommand), return that path.
// Otherwise, returns the path of the latest directory
func jsonDir(args []string) (string, error) {
	var err error
	var dirs jsonDirs

	if 0 < len(args) {
		if dirs, err = lsValidJSONDirs(); err != nil {
			return "", err
		}

		path := filepath.Join(c.Conf.ResultsDir, args[0])
		for _, d := range dirs {
			ss := strings.Split(d, string(os.PathSeparator))
			timedir := ss[len(ss)-1]
			if timedir == args[0] {
				return path, nil
			}
		}

		return "", fmt.Errorf("Invalid path: %s", path)
	}

	// PIPE
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("Failed to read stdin: %s", err)
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			return filepath.Join(c.Conf.ResultsDir, fields[0]), nil
		}
		return "", fmt.Errorf("Stdin is invalid: %s", string(bytes))
	}

	// returns latest dir when no args or no PIPE
	if dirs, err = lsValidJSONDirs(); err != nil {
		return "", err
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("No results under %s",
			c.Conf.ResultsDir)
	}
	return dirs[0], nil
}

// loadOneScanHistory read JSON data
func loadOneScanHistory(jsonDir string) (scanHistory models.ScanHistory, err error) {
	var results []models.ScanResult
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonDir, err)
		return
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" {
			continue
		}
		var r models.ScanResult
		var data []byte
		path := filepath.Join(jsonDir, f.Name())
		if data, err = ioutil.ReadFile(path); err != nil {
			err = fmt.Errorf("Failed to read %s: %s", path, err)
			return
		}
		if json.Unmarshal(data, &r) != nil {
			err = fmt.Errorf("Failed to parse %s: %s", path, err)
			return
		}
		results = append(results, r)
	}
	if len(results) == 0 {
		err = fmt.Errorf("There is no json file under %s", jsonDir)
		return
	}

	scanHistory = models.ScanHistory{
		ScanResults: results,
	}
	return
}
