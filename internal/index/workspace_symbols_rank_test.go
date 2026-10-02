package index

import "testing"

func TestSymbolNameScoreRanksLikeAnIDE(t *testing.T) {
	order := func(query string, names ...string) {
		t.Helper()
		for index := 1; index < len(names); index++ {
			if symbolNameScore(names[index-1], query) <= symbolNameScore(names[index], query) {
				t.Errorf("%q: %q should rank above %q", query, names[index-1], names[index])
			}
		}
	}
	order("ColorsServ", "ColorsService", "ColorsServiceImpl", "colorsService")
	order("CSI", "ColorsServiceImpl", "csize")
	for query, name := range map[string]string{
		"ColorsServ": "ColorApplicationsServiceImpl has a @Service-annotation",
		"CSI":        "Closing",
	} {
		if symbolNameScore(name, query) >= 0 {
			t.Errorf("%q should not match %q", query, name)
		}
	}
	if !camelHumpsMatch("ColorsServiceImpl", "CoSeImp") || !camelHumpsMatch("ColorsServiceImpl", "CSImpl") {
		t.Error("camel humps with word prefixes should match")
	}
}
