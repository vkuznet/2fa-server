package main

// templates module
//
// Copyright (c) 2019 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"bytes"
	"html/template"
	"path/filepath"
)

// TmplRecord represent template record
type TmplRecord map[string]interface{}

// consume list of templates and release their full path counterparts
func fileNames(tdir string, filenames ...string) []string {
	flist := []string{}
	for _, fname := range filenames {
		flist = append(flist, filepath.Join(tdir, fname))
	}
	return flist
}

// parse template with given data
func parseTmpl(tdir, tmpl string, data interface{}) string {
	buf := new(bytes.Buffer)
	filenames := fileNames(tdir, tmpl)
	t := template.Must(template.New(tmpl).ParseFiles(filenames...))
	err := t.Execute(buf, data)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

// ServerTemplates structure
type Templates struct {
	html string
}

// Tmpl method for Templates structure
func (t Templates) Tmpl(tdir, tfile string, tmplData map[string]interface{}) string {
	if t.html != "" {
		return t.html
	}
	t.html = parseTmpl(Config.Templates, tfile, tmplData)
	return t.html
}
