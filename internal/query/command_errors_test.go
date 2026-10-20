// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"errors"
	"strings"
	"testing"
)

// Malformed commands are refused with a positioned error that says what
// the command expects.
func TestCommandErrors(t *testing.T) {
	for src, want := range map[string]string{
		`nomv`:                                 "nomv expects",
		`nomv a b`:                             "unexpected",
		`nomv bogus=1 a`:                       "unexpected",
		`mvcombine delim= a`:                   "mvcombine expects",
		`mvcombine`:                            "mvcombine expects",
		`strcat allrequired=maybe a b c`:       "",
		`strcat a`:                             "strcat expects",
		`strcat a b "lit"`:                     "strcat expects",
		`strcat a , c`:                         "unexpected",
		`rangemap field=n`:                     "rangemap expects",
		`rangemap low=0-1`:                     "rangemap expects",
		`rangemap field=n low=`:                "rangemap low= needs a value",
		`rangemap field=n default=a-b low=0-1`: "rangemap default= needs a name",
		`rangemap field=n low=0-1 low=2-3`:     "needs a new name",
		`rangemap field=n low=abc`:             "needs a range like 0-100",
		`rangemap field=n low=5`:               "needs a range like 0-100",
		`rangemap field=n 5`:                   "unexpected",
		`accum`:                                "accum",
		`accum a b`:                            "",
		`delta`:                                "delta",
		`delta a p=x`:                          "",
		`delta a p=0`:                          "",
		`autoregress`:                          "autoregress",
		`autoregress a p=x`:                    "",
		`autoregress a p=3-1`:                  "",
		`autoregress a p=1-2 as b`:             "",
		`fieldsummary maxvals=x`:               "",
		`trendline`:                            "trendline",
		`trendline sma(a)`:                     "",
		`trendline foo2(a)`:                    "",
		`trendline sma2(a) as`:                 "",
		`makemv`:                               "makemv",
		`makemv tokenizer="(" a`:               "",
		`makemv delim= a`:                      "",
		`makemv allowempty=x a`:                "",
		`mvexpand`:                             "mvexpand",
		`mvexpand a limit=x`:                   "",
		`addtotals row=x`:                      "",
		`addtotals bogus=1`:                    "",
		`convert`:                              "convert",
		`convert bogus(a)`:                     "",
		`convert ctime(a) as`:                  "",
		`convert timeformat= ctime(a)`:         "",
		`xmlkv a b`:                            "",
		`xpath`:                                "xpath",
		`xpath field=a`:                        "",
		`xpath bogus=1 "//a"`:                  "",
		`outputlookup`:                         "outputlookup",
		`outputlookup BAD.csv`:                 "",
		`outputlookup append=x t`:              "",
		`outputlookup bogus=1 t`:               "",
		`outputlookup t u`:                     "",
		`extract bogus=1`:                      "",
		`extract pairdelim=`:                   "",
		`setfields`:                            "setfields",
		`setfields a`:                          "",
		`predict`:                              "predict",
		`predict a algorithm=bogus`:            "",
		`predict a future_timespan=x`:          "",
		`predict a holdback=x`:                 "",
		`predict a upper=x`:                    "",
		`predict a bogus=1`:                    "",
		`kmeans k=x a`:                         "",
		`kmeans k=0 a`:                         "",
		`kmeans bogus=1 a`:                     "",
		`iplocation`:                           "iplocation",
		`iplocation allfields=x a`:             "",
		`iplocation a b`:                       "",
		`anomalydetection action=bogus a`:      "",
		`anomalydetection method=bogus a`:      "",
		`concurrency`:                          "concurrency",
		`concurrency duration=`:                "",
		`contingency a`:                        "contingency",
		`contingency maxrows=x a b`:            "",
		`cluster t=x field=a`:                  "",
		`cluster bogus=1`:                      "",
		`timewrap`:                             "timewrap",
		`timewrap x`:                           "",
		`timewrap 1h series=bogus`:             "",
		`abstract maxlines=x`:                  "",
		`return x=`:                            "",
		`return 0 a`:                           "",
		`format maxresults=x`:                  "",
		`format "("`:                           "",
		`replace "a" with`:                     "",
		`replace "a" in b`:                     "",
		`replace "a" with "b" in`:              "",
		`foreach a`:                            "",
		`foreach a [stats count]`:              "",
		`fromjson`:                             "fromjson",
		`fromjson a prefix=`:                   "",
		`untable a b`:                          "untable",
		`xyseries a b`:                         "xyseries",
		`streamstats window=x count`:           "",
		`streamstats current=x count`:          "",
		`bin`:                                  "bin",
		`bin a span=x`:                         "",
		`spath bogus=1`:                        "",
		`spath input=`:                         "",
		`fillnull value=`:                      "",
		`dedup`:                                "dedup",
		`dedup 0 a`:                            "",
		`tail x`:                               "",
		`transpose x`:                          "",
		`transpose column_name=`:               "",
		`outlier action=bogus`:                 "",
		`outlier param=x`:                      "",
		`gauge`:                                "gauge",
		`gauge a x`:                            "",
		`highlight`:                            "highlight",
		`set bogus [search a] [search b]`:      "",
		`set union [search a]`:                 "",
		`multisearch [search a]`:               "",
		`union`:                                "union",
		`map`:                                  "map",
		`map search=`:                          "",
		`map search="x" maxsearches=x`:         "",
		`makeresults count=x`:                  "",
		`makeresults count=0`:                  "",
		`eventcount bogus=1`:                   "",
		`from`:                                 "from",
		`from bogus:x`:                         "",
	} {
		_, err := Parse("* | " + src)
		if err == nil {
			t.Errorf("%s: parsed", src)
			continue
		}
		var pe *Error
		if !errors.As(err, &pe) {
			t.Errorf("%s: error %T is not positioned", src, err)
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", src, err, want)
		}
	}
}

func TestRangeMapDefaultName(t *testing.T) {
	if got := (&RangeMap{}).DefaultName(); got != "None" {
		t.Errorf("default = %q", got)
	}
	if got := (&RangeMap{Default: "other"}).DefaultName(); got != "other" {
		t.Errorf("default = %q", got)
	}
}
