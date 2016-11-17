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

// JSONDirPattern is file name pattern of JSON directory
var JSONDirPattern = regexp.MustCompile(`^\d{8}_\d{4}$`)

// JSONDirs array of json files path.
type JSONDirs []string

func (d JSONDirs) Len() int {
	return len(d)
}
func (d JSONDirs) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d JSONDirs) Less(i, j int) bool {
	return d[j] < d[i]
}

// getValidJSONDirs return valid json directory as array
func getValidJSONDirs() (jsonDirs JSONDirs, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(c.Conf.ResultsDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", c.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && JSONDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(c.Conf.ResultsDir, d.Name())
			jsonDirs = append(jsonDirs, jsonDir)
		}
	}
	sort.Sort(jsonDirs)
	return
}

func selectScanHistory(jsonDirName string) (history models.ScanHistory, err error) {
	var jsonDir string
	if 0 < len(jsonDirName) {
		jsonDir = filepath.Join(c.Conf.ResultsDir, jsonDirName)
	} else {
		var jsonDirs JSONDirs
		if jsonDirs, err = getValidJSONDirs(); err != nil {
			return
		}
		if len(jsonDirs) == 0 {
			return history, fmt.Errorf("No scan results are found in %s", c.Conf.ResultsDir)
		}
		jsonDir = jsonDirs[0]
	}
	if history, err = loadOneScanHistory(jsonDir); err != nil {
		return
	}
	return
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
