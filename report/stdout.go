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

package report

import (
	"fmt"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// StdoutWriter write to stdout
type StdoutWriter struct{}

func (w StdoutWriter) Write(rs ...models.ScanResult) error {
	if c.Conf.FormatShortText {
		fmt.Print("\n\n")
		fmt.Println("Scan Summary")
		fmt.Println("============")
		fmt.Println(toOneLineSummary(rs))
		fmt.Print("\n")
	}

	if c.Conf.FormatFullText {
		for _, r := range rs {
			fmt.Println(toPlainText(r))
		}
	}
	return nil
}
