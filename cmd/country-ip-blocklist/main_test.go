package main

import (
	"reflect"
	"testing"
)

func TestParseCountries(t *testing.T) {
	got, err := parseCountries("cn, RU,cn")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CN", "RU"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCountries() = %v, want %v", got, want)
	}
}

func TestParseCountriesRejectsInvalidCode(t *testing.T) {
	if _, err := parseCountries("C1"); err == nil {
		t.Fatal("parseCountries() accepted an invalid country code")
	}
}
