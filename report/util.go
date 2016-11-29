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
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/gosuri/uitable"
)

func toOneLineSummary(rs []models.ScanResult) string {
	table := uitable.New()
	table.MaxColWidth = 100
	table.Wrap = true
	for _, r := range rs {
		cols := []interface{}{
			r.ServerInfo(),
			r.CveSummary(),
		}
		table.AddRow(cols...)
	}
	return fmt.Sprintf("%s\n", table)
}

func toPlainText(r models.ScanResult) (string, error) {
	serverInfo := r.ServerInfo()

	var buffer bytes.Buffer
	for i := 0; i < len(serverInfo); i++ {
		buffer.WriteString("=")
	}
	header := fmt.Sprintf("%s\n%s", serverInfo, buffer.String())

	if len(r.KnownCves) == 0 && len(r.UnknownCves) == 0 {
		return fmt.Sprintf(`
%s
No unsecure packages.
`, header), nil
	}

	summary := ToPlainTextSummary(r)
	scoredReport, unscoredReport := []string{}, []string{}
	scoredReport, unscoredReport = toPlainTextDetails(r, r.Family)

	unscored := ""
	if !config.Conf.IgnoreUnscoredCves {
		unscored = strings.Join(unscoredReport, "\n\n")
	}

	scored := strings.Join(scoredReport, "\n\n")
	detail := fmt.Sprintf(`
%s

%s
`,
		scored,
		unscored,
	)
	text := fmt.Sprintf("%s\n%s\n%s\n", header, summary, detail)

	return text, nil
}

// ToPlainTextSummary format summary for plain text.
func ToPlainTextSummary(r models.ScanResult) string {
	stable := uitable.New()
	stable.MaxColWidth = 84
	stable.Wrap = true

	cves := r.KnownCves
	if !config.Conf.IgnoreUnscoredCves {
		cves = append(cves, r.UnknownCves...)
	}

	for _, d := range cves {
		var scols []string

		switch {
		case config.Conf.Lang == "ja" &&
			0 < d.CveDetail.Jvn.CvssScore():

			summary := d.CveDetail.Jvn.CveTitle()
			scols = []string{
				d.CveDetail.CveID,
				fmt.Sprintf("%-4.1f (%s)",
					d.CveDetail.CvssScore(config.Conf.Lang),
					d.CveDetail.Jvn.CvssSeverity(),
				),
				summary,
			}
		case 0 < d.CveDetail.CvssScore("en"):
			summary := d.CveDetail.Nvd.CveSummary()
			scols = []string{
				d.CveDetail.CveID,
				fmt.Sprintf("%-4.1f (%s)",
					d.CveDetail.CvssScore(config.Conf.Lang),
					d.CveDetail.Nvd.CvssSeverity(),
				),
				summary,
			}
		default:
			scols = []string{
				d.CveDetail.CveID,
				"?",
				d.CveDetail.Nvd.CveSummary(),
			}
		}

		cols := make([]interface{}, len(scols))
		for i := range cols {
			cols[i] = scols[i]
		}
		stable.AddRow(cols...)
	}
	return fmt.Sprintf("%s", stable)
}

func toPlainTextDetails(r models.ScanResult, osFamily string) (scoredReport, unscoredReport []string) {
	for _, cve := range r.KnownCves {
		switch config.Conf.Lang {
		case "en":
			if 0 < cve.CveDetail.Nvd.CvssScore() {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangEn(cve, osFamily))
			} else {
				scoredReport = append(
					scoredReport, toPlainTextUnknownCve(cve, osFamily))
			}
		case "ja":
			if 0 < cve.CveDetail.Jvn.CvssScore() {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangJa(cve, osFamily))
			} else if 0 < cve.CveDetail.Nvd.CvssScore() {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangEn(cve, osFamily))
			} else {
				scoredReport = append(
					scoredReport, toPlainTextUnknownCve(cve, osFamily))
			}
		}
	}
	for _, cve := range r.UnknownCves {
		unscoredReport = append(
			unscoredReport, toPlainTextUnknownCve(cve, osFamily))
	}
	return
}

func toPlainTextUnknownCve(cveInfo models.CveInfo, osFamily string) string {
	cveID := cveInfo.CveDetail.CveID
	dtable := uitable.New()
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")
	dtable.AddRow("Score", "?")
	dtable.AddRow("NVD",
		fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("CVE Details",
		fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))

	dlinks := distroLinks(cveInfo, osFamily)
	for _, link := range dlinks {
		dtable.AddRow(link.title, link.url)
	}

	return fmt.Sprintf("%s", dtable)
}

func toPlainTextDetailsLangJa(cveInfo models.CveInfo, osFamily string) string {
	cveDetail := cveInfo.CveDetail
	cveID := cveDetail.CveID
	jvn := cveDetail.Jvn

	dtable := uitable.New()
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")
	if score := cveDetail.Jvn.CvssScore(); 0 < score {
		dtable.AddRow("Score",
			fmt.Sprintf("%4.1f (%s)",
				cveDetail.Jvn.CvssScore(),
				jvn.CvssSeverity(),
			))
	} else {
		dtable.AddRow("Score", "?")
	}
	dtable.AddRow("Vector", jvn.CvssVector())
	dtable.AddRow("Title", jvn.CveTitle())
	dtable.AddRow("Description", jvn.CveSummary())
	dtable.AddRow(cveDetail.CweID(), cweURL(cveDetail.CweID()))
	dtable.AddRow(cveDetail.CweID()+"(JVN)", cweJvnURL(cveDetail.CweID()))

	dtable.AddRow("JVN", jvn.Link())
	dtable.AddRow("NVD", fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
	dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
	dtable.AddRow("CVSS Claculator", cveDetail.CvssV2CalculatorLink("ja"))

	dlinks := distroLinks(cveInfo, osFamily)
	for _, link := range dlinks {
		dtable.AddRow(link.title, link.url)
	}

	dtable = addPackageInfos(dtable, cveInfo.Packages)
	dtable = addCpeNames(dtable, cveInfo.CpeNames)

	return fmt.Sprintf("%s", dtable)
}

func toPlainTextDetailsLangEn(d models.CveInfo, osFamily string) string {
	cveDetail := d.CveDetail
	cveID := cveDetail.CveID
	nvd := cveDetail.Nvd

	dtable := uitable.New()
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")

	if score := cveDetail.Nvd.CvssScore(); 0 < score {
		dtable.AddRow("Score",
			fmt.Sprintf("%4.1f (%s)",
				cveDetail.Nvd.CvssScore(),
				nvd.CvssSeverity(),
			))
	} else {
		dtable.AddRow("Score", "?")
	}

	dtable.AddRow("Vector", nvd.CvssVector())
	dtable.AddRow("Summary", nvd.CveSummary())
	dtable.AddRow("CWE", cweURL(cveDetail.CweID()))

	dtable.AddRow("NVD", fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
	dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
	dtable.AddRow("CVSS Claculator", cveDetail.CvssV2CalculatorLink("en"))

	links := distroLinks(d, osFamily)
	for _, link := range links {
		dtable.AddRow(link.title, link.url)
	}
	dtable = addPackageInfos(dtable, d.Packages)
	dtable = addCpeNames(dtable, d.CpeNames)

	return fmt.Sprintf("%s\n", dtable)
}

type distroLink struct {
	title string
	url   string
}

// addVendorSite add Vendor site of the CVE to table
func distroLinks(cveInfo models.CveInfo, osFamily string) []distroLink {
	cveID := cveInfo.CveDetail.CveID
	switch osFamily {
	case "rhel", "centos":
		links := []distroLink{
			{
				"RHEL-CVE",
				fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
			},
		}
		for _, advisory := range cveInfo.DistroAdvisories {
			aidURL := strings.Replace(advisory.AdvisoryID, ":", "-", -1)
			links = append(links, distroLink{
				//  "RHEL-errata",
				advisory.AdvisoryID,
				fmt.Sprintf(redhatRHSABaseBaseURL, aidURL),
			})
		}
		return links
	case "amazon":
		links := []distroLink{
			{
				"RHEL-CVE",
				fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
			},
		}
		for _, advisory := range cveInfo.DistroAdvisories {
			links = append(links, distroLink{
				//  "Amazon-ALAS",
				advisory.AdvisoryID,
				fmt.Sprintf(amazonSecurityBaseURL, advisory.AdvisoryID),
			})
		}
		return links
	case "ubuntu":
		return []distroLink{
			{
				"Ubuntu-CVE",
				fmt.Sprintf("%s/%s", ubuntuSecurityBaseURL, cveID),
			},
			//TODO Ubuntu USN
		}
	case "debian":
		return []distroLink{
			{
				"Debian-CVE",
				fmt.Sprintf("%s/%s", debianTrackerBaseURL, cveID),
			},
			//  TODO Debian dsa
		}
	case "FreeBSD":
		links := []distroLink{}
		for _, advisory := range cveInfo.DistroAdvisories {
			links = append(links, distroLink{
				"FreeBSD-VuXML",
				fmt.Sprintf(freeBSDVuXMLBaseURL, advisory.AdvisoryID),
			})
		}
		return links
	default:
		return []distroLink{}
	}
}

//TODO
// addPackageInfos add package information related the CVE to table
func addPackageInfos(table *uitable.Table, packs []models.PackageInfo) *uitable.Table {
	for i, p := range packs {
		var title string
		if i == 0 {
			title = "Package/CPE"
		}
		ver := fmt.Sprintf(
			"%s -> %s", p.ToStringCurrentVersion(), p.ToStringNewVersion())
		table.AddRow(title, ver)
	}
	return table
}

func addCpeNames(table *uitable.Table, names []models.CpeName) *uitable.Table {
	for _, p := range names {
		table.AddRow("CPE", fmt.Sprintf("%s", p.Name))
	}
	return table
}

func cweURL(cweID string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
		strings.TrimPrefix(cweID, "CWE-"))
}

func cweJvnURL(cweID string) string {
	return fmt.Sprintf("http://jvndb.jvn.jp/ja/cwe/%s.html", cweID)
}
