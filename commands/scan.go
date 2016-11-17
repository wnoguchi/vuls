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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// ScanCmd is Subcommand of host discovery mode
type ScanCmd struct {
	lang             string
	debug            bool
	debugSQL         bool
	configPath       string
	resultsDir       string
	cvedbtype        string
	cvedbpath        string
	cveDictionaryURL string
	cacheDBPath      string
	httpProxy        string
	askKeyPassword   bool
	containersOnly   bool
	skipBroken       bool
	sshExternal      bool
}

// Name return subcommand name
func (*ScanCmd) Name() string { return "scan" }

// Synopsis return synopsis
func (*ScanCmd) Synopsis() string { return "Scan vulnerabilities" }

// Usage return usage
func (*ScanCmd) Usage() string {
	return `scan:
	scan
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[-cve-dictionary-dbtype=sqlite3|mysql]
		[-cve-dictionary-dbpath=/path/to/cve.sqlite3 or mysql connection string]
		[-cve-dictionary-url=http://127.0.0.1:1323]
		[-cache-dbpath=/path/to/cache.db]
		[-ssh-external]
		[-containers-only]
		[-skip-broken]
		[-http-proxy=http://192.168.0.1:8080]
		[-ask-key-password]
		[-debug]
		[-debug-sql]

		[SERVER]...
`
}

// SetFlags set flag
func (p *ScanCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	f.StringVar(
		&p.cvedbtype,
		"cve-dictionary-dbtype",
		"sqlite3",
		"DB type for fetching CVE dictionary (sqlite3 or mysql)")

	f.StringVar(
		&p.cvedbpath,
		"cve-dictionary-dbpath",
		"",
		"/path/to/sqlite3 (For get cve detail from cve.sqlite3)")

	defaultURL := "http://127.0.0.1:1323"
	f.StringVar(
		&p.cveDictionaryURL,
		"cve-dictionary-url",
		defaultURL,
		"http://CVE.Dictionary")

	defaultCacheDBPath := filepath.Join(wd, "cache.db")
	f.StringVar(
		&p.cacheDBPath,
		"cache-dbpath",
		defaultCacheDBPath,
		"/path/to/cache.db (local cache of changelog for Ubuntu/Debian)")

	f.BoolVar(
		&p.sshExternal,
		"ssh-external",
		false,
		"Use external ssh command. Default: Use the Go native implementation")

	f.BoolVar(
		&p.containersOnly,
		"containers-only",
		false,
		"Scan containers only. Default: Scan both of hosts and containers")

	f.BoolVar(
		&p.skipBroken,
		"skip-broken",
		false,
		"[For CentOS] yum update changelog with --skip-broken option")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)

	f.BoolVar(
		&p.askKeyPassword,
		"ask-key-password",
		false,
		"Ask ssh privatekey password before scanning",
	)
}

// Execute execute
func (p *ScanCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			logrus.Error(err)
			return subcommands.ExitFailure
		}
	}

	c.Conf.Debug = p.debug
	err = c.Load(p.configPath, keyPass)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	logrus.Info("Start scanning")
	logrus.Infof("config: %s", p.configPath)
	if p.cvedbpath != "" {
		if p.cvedbtype == "sqlite3" {
			logrus.Infof("cve-dictionary: %s", p.cvedbpath)
		}
	} else {
		logrus.Infof("cve-dictionary: %s", p.cveDictionaryURL)
	}

	var servernames []string
	if 0 < len(f.Args()) {
		servernames = f.Args()
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			bytes, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				logrus.Errorf("Failed to read stdin: %s", err)
				return subcommands.ExitFailure
			}
			fields := strings.Fields(string(bytes))
			if 0 < len(fields) {
				servernames = fields
			}
		}
	}

	target := make(map[string]c.ServerInfo)
	for _, arg := range servernames {
		found := false
		for servername, info := range c.Conf.Servers {
			if servername == arg {
				target[servername] = info
				found = true
				break
			}
		}
		if !found {
			logrus.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		c.Conf.Servers = target
	}
	logrus.Debugf("%s", pp.Sprintf("%v", target))

	c.Conf.Lang = p.lang
	c.Conf.DebugSQL = p.debugSQL

	// logger
	Log := util.NewCustomLogger(c.ServerInfo{})
	scannedAt := time.Now()

	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CveDBType = p.cvedbtype
	c.Conf.CveDBPath = p.cvedbpath
	c.Conf.CveDictionaryURL = p.cveDictionaryURL
	c.Conf.CacheDBPath = p.cacheDBPath
	c.Conf.SSHExternal = p.sshExternal
	c.Conf.HTTPProxy = p.httpProxy
	c.Conf.ContainersOnly = p.containersOnly
	c.Conf.SkipBroken = p.skipBroken

	Log.Info("Validating Config...")
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	if ok, err := cveapi.CveClient.CheckHealth(); !ok {
		Log.Errorf("CVE HTTP server is not running. err: %s", err)
		Log.Errorf("Run go-cve-dictionary as server mode or specify -cve-dictionary-dbpath option")
		return subcommands.ExitFailure
	}

	Log.Info("Detecting Server/Contianer OS... ")
	if err := scan.InitServers(Log); err != nil {
		Log.Errorf("Failed to init servers: %s", err)
		return subcommands.ExitFailure
	}

	Log.Info("Checking sudo configuration... ")
	if err := scan.CheckIfSudoNoPasswd(Log); err != nil {
		Log.Errorf("Failed to sudo with nopassword via SSH. Define NOPASSWD in /etc/sudoers on target servers")
		return subcommands.ExitFailure
	}

	Log.Info("Detecting Platforms... ")
	scan.DetectPlatforms(Log)

	Log.Info("Scanning vulnerabilities... ")
	if errs := scan.Scan(); 0 < len(errs) {
		for _, e := range errs {
			Log.Errorf("Failed to scan. err: %s", e)
		}
		return subcommands.ExitFailure
	}

	scanResults, err := scan.GetScanResults()
	if err != nil {
		Log.Fatal(err)
		return subcommands.ExitFailure
	}

	//TODO write json at the end of scan
	Log.Info("Reporting...")
	filtered := scanResults.FilterByCvssOver()
	jsonWriter := report.JSONWriter{ScannedAt: scannedAt}
	if err := jsonWriter.Write(filtered); err != nil {
		Log.Fatalf("Failed to write to JSON file, err: %s", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
