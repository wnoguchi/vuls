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
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/kotakanbe/go-cve-dictionary/log"
)

// ReportCmd is Subcommand of host discovery mode
type ReportCmd struct {
	lang               string
	debug              bool
	configPath         string
	resultsDir         string
	cvssScoreOver      float64
	ignoreUnscoredCves bool
	httpProxy          string

	toSlack     bool
	toEMail     bool
	toLocalFile bool
	toS3        bool
	toAzureBlob bool

	formatJSON      bool
	formatPlainText bool
	formatXML       bool

	awsProfile  string
	awsS3Bucket string
	awsRegion   string

	azureAccount   string
	azureKey       string
	azureContainer string
}

// Name return subcommand name
func (*ReportCmd) Name() string { return "report" }

// Synopsis return synopsis
func (*ReportCmd) Synopsis() string { return "Reporting" }

// Usage return usage
func (*ReportCmd) Usage() string {
	return `report:
	report
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[-cvss-over=7]
		[-ignore-unscored-cves]
		[-to-email]
		[-to-slack]
		[-to-localfile]
		[-to-s3]
		[-to-azure-blob]
		[-format-json]
		[-format-xml]
		[-format-plaintext]
		[-aws-profile=default]
		[-aws-region=us-west-2]
		[-aws-s3-bucket=bucket_name]
		[-azure-account=accout]
		[-azure-key=key]
		[-azure-container=container]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]

		[SERVER]...
`
}

// SetFlags set flag
func (p *ReportCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	f.Float64Var(
		&p.cvssScoreOver,
		"cvss-over",
		0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(
		&p.ignoreUnscoredCves,
		"ignore-unscored-cves",
		false,
		"Don't report the unscored CVEs")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.formatJSON,
		"format-json",
		false,
		fmt.Sprintf("Write report by JSON format"))

	f.BoolVar(&p.formatPlainText,
		"format-plaintext",
		false,
		fmt.Sprintf("Write report by plain text format"))

	f.BoolVar(&p.formatXML,
		"format-xml",
		false,
		fmt.Sprintf("Write report by XML format"))

	f.BoolVar(&p.toSlack, "to-slack", false, "Send report via Slack")
	f.BoolVar(&p.toEMail, "to-email", false, "Send report via Email")
	f.BoolVar(&p.toLocalFile,
		"to-localfile",
		false,
		fmt.Sprintf("write report to TODO"))

	f.BoolVar(&p.toS3,
		"to-s3",
		false,
		"Write report to S3 (bucket/yyyyMMdd_HHmm/servername.json/xml/txt)")
	f.StringVar(&p.awsProfile, "aws-profile", "default", "AWS profile to use")
	f.StringVar(&p.awsRegion, "aws-region", "us-east-1", "AWS region to use")
	f.StringVar(&p.awsS3Bucket, "aws-s3-bucket", "", "S3 bucket name")

	f.BoolVar(&p.toAzureBlob,
		"to-azure-blob",
		false,
		"Write report to Azure Storage blob (container/yyyyMMdd_HHmm/servername.json/xml/txt)")
	f.StringVar(&p.azureAccount,
		"azure-account",
		"",
		"Azure account name to use. AZURE_STORAGE_ACCOUNT environment variable is used if not specified")
	f.StringVar(&p.azureKey,
		"azure-key",
		"",
		"Azure account key to use. AZURE_STORAGE_ACCESS_KEY environment variable is used if not specified")
	f.StringVar(&p.azureContainer, "azure-container", "", "Azure storage container name")
}

// Execute execute
func (p *ReportCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	if err := c.Load(p.configPath, ""); err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.Debug = p.debug
	c.Conf.Lang = p.lang

	logrus.Info("Start reporting")
	logrus.Infof("config: %s", p.configPath)

	// logger
	Log := util.NewCustomLogger(c.ServerInfo{})

	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CvssScoreOver = p.cvssScoreOver
	c.Conf.IgnoreUnscoredCves = p.ignoreUnscoredCves
	c.Conf.HTTPProxy = p.httpProxy

	jsonDir, err := jsonDir(f.Args())
	if err != nil {
		log.Errorf("Failed to read from JSON: %s", err)
		return subcommands.ExitFailure
	}

	// report
	reports := []report.ResultWriter{
		report.StdoutWriter{},
	}

	if p.toSlack {
		reports = append(reports, report.SlackWriter{})
	}

	if p.toEMail {
		reports = append(reports, report.EMailWriter{})
	}

	if p.toLocalFile {
		reports = append(reports, report.LocalFileWriter{
			CurrentDir:      jsonDir,
			FormatXML:       p.formatXML,
			FormatPlainText: p.formatPlainText,
		})
	}

	if p.toS3 {
		c.Conf.AwsRegion = p.awsRegion
		c.Conf.AwsProfile = p.awsProfile
		c.Conf.S3Bucket = p.awsS3Bucket
		if err := report.CheckIfBucketExists(); err != nil {
			Log.Errorf("Check if there is a bucket beforehand: %s, err: %s", c.Conf.S3Bucket, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.S3Writer{
			FormatXML:       p.formatXML,
			FormatJSON:      p.formatJSON,
			FormatPlainText: p.formatPlainText,
		})
	}

	if p.toAzureBlob {
		c.Conf.AzureAccount = p.azureAccount
		if len(c.Conf.AzureAccount) == 0 {
			c.Conf.AzureAccount = os.Getenv("AZURE_STORAGE_ACCOUNT")
		}

		c.Conf.AzureKey = p.azureKey
		if len(c.Conf.AzureKey) == 0 {
			c.Conf.AzureKey = os.Getenv("AZURE_STORAGE_ACCESS_KEY")
		}

		c.Conf.AzureContainer = p.azureContainer
		if len(c.Conf.AzureContainer) == 0 {
			Log.Error("Azure storage container name is requied with --azure-container option")
			return subcommands.ExitUsageError
		}
		if err := report.CheckIfAzureContainerExists(); err != nil {
			Log.Errorf("Check if there is a container beforehand: %s, err: %s", c.Conf.AzureContainer, err)
			return subcommands.ExitUsageError
		}
		reports = append(reports, report.AzureBlobWriter{
			FormatXML:       p.formatXML,
			FormatJSON:      p.formatJSON,
			FormatPlainText: p.formatPlainText,
		})
	}

	// Go routine
	history, err := loadOneScanHistory(jsonDir)
	for _, r := range history.ScanResults {
		if err != nil {
			log.Errorf("Failed to read from JSON: %s", err)
			return subcommands.ExitFailure
		}

		Log.Info("Reporting...")
		filtered := r.FilterByCvssOver()
		for _, w := range reports {
			if err := w.Write(filtered); err != nil {
				Log.Fatalf("Failed to report, err: %s", err)
				return subcommands.ExitFailure
			}
		}
	}

	return subcommands.ExitSuccess
}
