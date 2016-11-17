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
	"time"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$`)

// JSONDirs array of json files path.
type jsonDirs []string

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

func jsonDir(args []string) (string, error) {
	var err error
	if 0 < len(args) {
		path := filepath.Join(c.Conf.ResultsDir, args[0])

		var dirs jsonDirs
		if dirs, err = lsValidJSONDirs(); err != nil {
			return "", fmt.Errorf(
				"Directory not found: %s, err: %s", path, err)
		}

		for _, d := range dirs {
			splitPath := strings.Split(d, string(os.PathSeparator))
			timedir := splitPath[len(splitPath)-1]
			if timedir == args[0] {
				return path, nil
			}
		}

		return "", fmt.Errorf(
			"Directory not found: %s, err : %s", path, err)
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

		return "", fmt.Errorf("stdin is invalid: %s", string(bytes))
	}

	// No args
	var dirs jsonDirs
	if dirs, err = lsValidJSONDirs(); err != nil {
		return "", fmt.Errorf("Directory not found. err: %s", err)
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("No results under %s, err: %s",
			filepath.Join(c.Conf.ResultsDir, dirs[0]), err)
	}
	return dirs[0], nil
}

// loadOneScanHistory read JSON data
func loadOneScanHistory(jsonDir string) (scanHistory models.ScanHistory, err error) {
	var scanResults []models.ScanResult
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonDir, err)
		return
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		var scanResult models.ScanResult
		var data []byte
		jsonPath := filepath.Join(jsonDir, file.Name())
		if data, err = ioutil.ReadFile(jsonPath); err != nil {
			err = fmt.Errorf("Failed to read %s: %s", jsonPath, err)
			return
		}
		if json.Unmarshal(data, &scanResult) != nil {
			err = fmt.Errorf("Failed to parse %s: %s", jsonPath, err)
			return
		}
		scanResults = append(scanResults, scanResult)
	}
	if len(scanResults) == 0 {
		err = fmt.Errorf("There is no json file under %s", jsonDir)
		return
	}

	var scannedAt time.Time
	if scanResults[0].ScannedAt.IsZero() {
		splitPath := strings.Split(jsonDir, string(os.PathSeparator))
		timeStr := splitPath[len(splitPath)-1]
		if scannedAt, err = time.Parse(time.RFC3339, timeStr); err != nil {
			err = fmt.Errorf("Failed to parse %s: %s", timeStr, err)
			return
		}
	} else {
		scannedAt = scanResults[0].ScannedAt
	}

	scanHistory = models.ScanHistory{
		ScanResults: scanResults,
		ScannedAt:   scannedAt,
	}
	return
}
