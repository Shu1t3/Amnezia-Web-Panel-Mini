package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/cache"
)

var translations = make(map[string]map[string]string)
var translationsCache = cache.NewTranslationsCache()

func LoadTranslations(transDir string) {
	entries, err := os.ReadDir(transDir)
	if err != nil {
		return
	}
	for _, f := range entries {
		if strings.HasSuffix(f.Name(), ".json") {
			lang := strings.TrimSuffix(f.Name(), ".json")
			b, err := os.ReadFile(filepath.Join(transDir, f.Name()))
			if err == nil {
				var data map[string]string
				if json.Unmarshal(b, &data) == nil {
					translations[lang] = data
				}
			}
		}
	}
	translationsCache.Load(translations)
}

func GetTranslation(lang, textID string) string {
	if langMap, ok := translations[lang]; ok {
		if val, ok2 := langMap[textID]; ok2 {
			return val
		}
	}
	if langMap, ok := translations["en"]; ok {
		if val, ok2 := langMap[textID]; ok2 {
			return val
		}
	}
	return textID
}
