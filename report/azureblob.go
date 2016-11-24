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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/storage"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// AzureBlobWriter writes results to AzureBlob
type AzureBlobWriter struct{}

// Write results to Azure Blob storage
func (w AzureBlobWriter) Write(rs ...models.ScanResult) (err error) {
	cli, err := getBlobClient()
	if err != nil {
		return err
	}

	if c.Conf.FormatSummaryText {
		timestr := rs[0].ScannedAt.Format(time.RFC3339)
		k := fmt.Sprintf(timestr + "/summary.txt")
		text := toOneLineSummary(rs)
		b := []byte(text)
		if err = cli.CreateBlockBlobFromReader(
			c.Conf.AzureContainer,
			k,
			uint64(len(b)),
			bytes.NewReader(b),
			map[string]string{},
		); err != nil {
			return fmt.Errorf("%s/%s, %s",
				c.Conf.AzureContainer, k, err)
		}
	}

	for _, r := range rs {
		key := r.ReportKeyName()
		if c.Conf.FormatJSON {
			k := key + ".json"
			var b []byte
			if b, err = json.Marshal(r); err != nil {
				return fmt.Errorf("Failed to Marshal to JSON: %s", err)
			}

			if err = cli.CreateBlockBlobFromReader(
				c.Conf.AzureContainer,
				k,
				uint64(len(b)),
				bytes.NewReader(b),
				map[string]string{},
			); err != nil {
				return fmt.Errorf("%s/%s, %s",
					c.Conf.AzureContainer, k, err)
			}
		}

		if c.Conf.FormatDetailText {
			k := key + ".txt"
			text, err := toPlainText(r)
			if err != nil {
				return err
			}
			b := []byte(text)

			if err = cli.CreateBlockBlobFromReader(
				c.Conf.AzureContainer,
				k,
				uint64(len(b)),
				bytes.NewReader(b),
				map[string]string{},
			); err != nil {
				return fmt.Errorf("%s/%s, %s",
					c.Conf.AzureContainer, k, err)
			}
		}

		if c.Conf.FormatXML {
			k := key + ".xml"
			var b []byte
			if b, err = xml.Marshal(r); err != nil {
				return fmt.Errorf("Failed to Marshal to XML: %s", err)
			}
			allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})

			if err = cli.CreateBlockBlobFromReader(
				c.Conf.AzureContainer,
				k,
				uint64(len(allBytes)),
				bytes.NewReader(allBytes),
				map[string]string{},
			); err != nil {
				return fmt.Errorf("%s/%s, %s",
					c.Conf.AzureContainer, k, err)
			}
		}
	}
	return
}

// CheckIfAzureContainerExists check the existence of Azure storage container
func CheckIfAzureContainerExists() error {
	cli, err := getBlobClient()
	if err != nil {
		return err
	}
	ok, err := cli.ContainerExists(c.Conf.AzureContainer)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Container not found. Container: %s", c.Conf.AzureContainer)
	}
	return nil
}

func getBlobClient() (storage.BlobStorageClient, error) {
	api, err := storage.NewBasicClient(c.Conf.AzureAccount, c.Conf.AzureKey)
	if err != nil {
		return storage.BlobStorageClient{}, err
	}
	return api.GetBlobService(), nil
}
