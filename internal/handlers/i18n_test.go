package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestTranslations(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	translations = make(map[string]map[string]string)

	enData := `{"hello":"Hello","welcome":"Welcome","login":"Login","error":"Error"}`
	ruData := `{"hello":"Привет","welcome":"Добро пожаловать","login":"Вход","error":"Ошибка"}`

	if err := os.WriteFile(filepath.Join(dir, "en.json"), []byte(enData), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ru.json"), []byte(ruData), 0644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestLoadTranslations(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	if _, ok := translations["en"]; !ok {
		t.Error("English translations not loaded")
	}
	if _, ok := translations["ru"]; !ok {
		t.Error("Russian translations not loaded")
	}
}

func TestLoadTranslations_NonexistentDir(t *testing.T) {
	LoadTranslations("/nonexistent/path")
	// Should not panic
}

func TestLoadTranslations_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	translations = make(map[string]map[string]string)

	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not json"), 0644)
	LoadTranslations(dir)

	if _, ok := translations["bad"]; ok {
		t.Error("invalid JSON should not be loaded")
	}
}

func TestGetTranslation_Found(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	val := GetTranslation("en", "hello")
	if val != "Hello" {
		t.Errorf("expected 'Hello', got '%s'", val)
	}
}

func TestGetTranslation_Russian(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	val := GetTranslation("ru", "hello")
	if val != "Привет" {
		t.Errorf("expected 'Привет', got '%s'", val)
	}
}

func TestGetTranslation_FallbackToEnglish(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	val := GetTranslation("fr", "hello")
	if val != "Hello" {
		t.Errorf("expected fallback to English 'Hello', got '%s'", val)
	}
}

func TestGetTranslation_NotFound(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	val := GetTranslation("en", "nonexistent_key")
	if val != "nonexistent_key" {
		t.Errorf("expected key returned as fallback, got '%s'", val)
	}
}

func TestGetTranslation_EmptyTranslations(t *testing.T) {
	translations = make(map[string]map[string]string)

	val := GetTranslation("en", "hello")
	if val != "hello" {
		t.Errorf("expected key returned when no translations, got '%s'", val)
	}
}

func TestGetTranslation_EmptyLang(t *testing.T) {
	dir := setupTestTranslations(t)
	LoadTranslations(dir)

	val := GetTranslation("", "hello")
	if val != "Hello" {
		t.Errorf("expected fallback to English for empty lang, got '%s'", val)
	}
}

func TestLoadTranslations_NonJSONFile(t *testing.T) {
	dir := t.TempDir()
	translations = make(map[string]map[string]string)

	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a json file"), 0644)
	LoadTranslations(dir)

	// Should not load .txt files
	if len(translations) != 0 {
		t.Error("non-JSON files should not be loaded")
	}
}
