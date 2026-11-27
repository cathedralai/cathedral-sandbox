package vmdisk

import (
	"strings"
	"testing"
)

// goodDump is the shape of `cryptsetup luksDump --dump-json-metadata` for a
// volume F3 makes and step 4 completes (an M slot and a recovery slot).
const goodDump = `{"keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},` +
	`"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},` +
	`"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"AA=="}},` +
	`"1":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},` +
	`"area":{"type":"raw","offset":"290816","size":"258048","encryption":"aes-xts-plain64","key_size":64},` +
	`"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"AA=="}}},` +
	`"tokens":{},"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0",` +
	`"encryption":"aes-xts-plain64","sector_size":4096}},` +
	`"digests":{"0":{"type":"pbkdf2","keyslots":["0","1"],"segments":["0"],"hash":"sha256","iterations":1000,"salt":"AA==","digest":"AA=="}},` +
	`"config":{"json_size":"12288","keyslots_size":"16744448"}}`

func TestHeaderRulesAcceptOurLayout(t *testing.T) {
	h := ParseHeader([]byte(goodDump))
	if !h.Parsed || !h.RulesOK || len(h.Keyslots) != 2 || h.Keyslots[0] != 0 || h.Keyslots[1] != 1 {
		t.Fatalf("%+v", h)
	}
	// Slot numbers mean nothing: a pruned header with only slot 1 passes.
	pruned := strings.Replace(goodDump, `"0":{"type":"luks2"`, `"5":{"type":"luks2"`, 1)
	if h := ParseHeader([]byte(pruned)); !h.RulesOK || h.Keyslots[0] != 1 || h.Keyslots[1] != 5 {
		t.Fatalf("pruned %+v", h)
	}
}

func TestHeaderRulesRefuseEveryEdit(t *testing.T) {
	for name, edit := range map[string][2]string{
		"null segment":         {`"encryption":"aes-xts-plain64","sector_size"`, `"encryption":"cipher_null-ecb","sector_size"`},
		"512 sectors":          {`"sector_size":4096`, `"sector_size":512`},
		"sector as string":     {`"sector_size":4096`, `"sector_size":"4096"`},
		"segment offset":       {`"offset":"16777216"`, `"offset":"2097152"`},
		"fixed size":           {`"size":"dynamic"`, `"size":"1048576"`},
		"iv tweak":             {`"iv_tweak":"0"`, `"iv_tweak":"8"`},
		"integrity":            {`"sector_size":4096}`, `"sector_size":4096,"integrity":{"type":"hmac(sha256)"}}`},
		"segment flags":        {`"sector_size":4096}`, `"sector_size":4096,"flags":["backup-final"]}`},
		"second segment":       {`"sector_size":4096}}`, `"sector_size":4096},"1":{"type":"linear"}}`},
		"null keyslot":         {`"size":"258048","encryption":"aes-xts-plain64"`, `"size":"258048","encryption":"cipher_null-ecb"`},
		"256-bit keyslot":      {`{"type":"luks2","key_size":64,`, `{"type":"luks2","key_size":32,`},
		"256-bit area key":     {`"encryption":"aes-xts-plain64","key_size":64},"kdf"`, `"encryption":"aes-xts-plain64","key_size":32},"kdf"`},
		"luks1 keyslot type":   {`{"type":"luks2","key_size":64,`, `{"type":"reencrypt","key_size":64,`},
		"requirement":          {`"keyslots_size":"16744448"}`, `"keyslots_size":"16744448","requirements":{"mandatory":["online-reencrypt"]}}`},
		"config flags":         {`"keyslots_size":"16744448"}`, `"keyslots_size":"16744448","flags":["allow-discards"]}`},
		"no config":            {`,"config":{"json_size":"12288","keyslots_size":"16744448"}`, ``},
		"no keyslot":           {`"keyslots":{"0"`, `"keyslots":{},"x":{"0"`},
		"duplicate segment":    {`"segments":{"0":{`, `"segments":{"0":{},"0":{`},
		"keyslot id 01":        {`"keyslots":{"0":`, `"keyslots":{"01":`},
		"trailing data":        {goodDump, goodDump + `{}`},
		"not json":             {goodDump, `LUKS`},
		"segment cipher upper": {`"encryption":"aes-xts-plain64","sector_size"`, `"encryption":"AES-XTS-PLAIN64","sector_size"`},
	} {
		raw := strings.Replace(goodDump, edit[0], edit[1], 1)
		if raw == goodDump {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if h := ParseHeader([]byte(raw)); h.RulesOK {
			t.Errorf("%s: passed the rules", name)
		}
	}
}

func TestHeaderParseKeepsKeyslotsWhenRulesFail(t *testing.T) {
	raw := strings.Replace(goodDump, `"sector_size":4096`, `"sector_size":512`, 1)
	h := ParseHeader([]byte(raw))
	if !h.Parsed || h.RulesOK || len(h.Keyslots) != 2 {
		t.Fatalf("%+v", h)
	}
	none := strings.Replace(goodDump, goodDump[len(`{"keyslots":`):strings.Index(goodDump, `,"tokens"`)], `{}`, 1)
	if h := ParseHeader([]byte(none)); !h.Parsed || h.RulesOK || len(h.Keyslots) != 0 {
		t.Fatalf("no keyslot: %+v", h)
	}
	if h := ParseHeader([]byte(`{"keyslots":{"0":{},"0":{}}}`)); h.Parsed {
		t.Fatal("a duplicate keyslot parsed")
	}
}

func TestCryptTable(t *testing.T) {
	const dev, sectors = "253:4", uint64(63 * MiB / 512)
	length := sectors - 32768
	good := "aes-xts-plain64 :64:logon:cryptsetup:abc-d0 0 253:4 32768 2 sector_size:4096 iv_large_sectors"
	if err := CheckCryptTable("crypt", 0, length, good, dev, sectors); err != nil {
		t.Fatal(err)
	}
	if err := CheckCryptTable("crypt", 0, length, "aes-xts-plain64 0011 0 253:4 32768 1 sector_size:4096", dev, sectors); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		kind   string
		start  uint64
		length uint64
		params string
	}{
		"linear":          {"linear", 0, length, good},
		"start":           {"crypt", 8, length, good},
		"length":          {"crypt", 0, length + 8, good},
		"null cipher":     {"crypt", 0, length, strings.Replace(good, "aes-xts-plain64", "cipher_null-ecb", 1)},
		"other device":    {"crypt", 0, length, strings.Replace(good, "253:4", "253:5", 1)},
		"offset":          {"crypt", 0, length, strings.Replace(good, " 32768 ", " 4096 ", 1)},
		"iv offset":       {"crypt", 0, length, strings.Replace(good, "-d0 0 ", "-d0 8 ", 1)},
		"512 sectors":     {"crypt", 0, length, strings.Replace(good, "sector_size:4096", "sector_size:512", 1)},
		"no options":      {"crypt", 0, length, "aes-xts-plain64 00 0 253:4 32768"},
		"no sector size":  {"crypt", 0, length, "aes-xts-plain64 00 0 253:4 32768 1 iv_large_sectors"},
		"option count":    {"crypt", 0, length, strings.Replace(good, " 2 sector", " 3 sector", 1)},
		"integrity":       {"crypt", 0, length, good + " integrity:28:aead"},
		"unknown option":  {"crypt", 0, length, strings.Replace(good, " 2 ", " 3 ", 1) + " future_option"},
		"truncated table": {"crypt", 0, length, "aes-xts-plain64"},
	} {
		if err := CheckCryptTable(c.kind, c.start, c.length, c.params, dev, sectors); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCryptsetupFloor(t *testing.T) {
	for out, ok := range map[string]bool{
		"cryptsetup 2.8.4 flags: UDEV BLKID KEYRING": true,
		"cryptsetup 2.8.1":                           true,
		"cryptsetup 2.10.0":                          true,
		"cryptsetup 3.0":                             true,
		"cryptsetup 2.8.0":                           false,
		"cryptsetup 2.7.0 flags: UDEV":               false,
		"cryptsetup 2.8.1-rc1":                       true,
		"cryptsetup two":                             false,
		"veritysetup 2.8.4":                          false,
		"":                                           false,
	} {
		if err := CheckCryptsetupVersion(out); (err == nil) != ok {
			t.Errorf("%q: %v", out, err)
		}
	}
}
