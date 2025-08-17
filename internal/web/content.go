package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"reflect"
)

//go:embed templates static
var ContentFS embed.FS

func GetHTMLTemplate(name string) (*template.Template, error) {

	funcMap := template.FuncMap{
		"reverse": reverseFunc,
	}
	templateFS, _ := fs.Sub(ContentFS, "templates")

	return template.New(name).Funcs(funcMap).ParseFS(templateFS, "common/*.tmpl.*", name+".tmpl.html")
}

// indirect returns the item at the end of indirection, and a bool to indicate
// if it's nil. If the returned bool is true, the returned value's kind will be
// either a pointer or interface.
func indirect(v reflect.Value) (rv reflect.Value, isNil bool) {
	for ; v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface; v = v.Elem() {
		if v.IsNil() {
			return v, true
		}
	}
	return v, false
}

// indirectInterface returns the concrete value in an interface value,
// or else the zero reflect.Value.
// That is, if v represents the interface value x, the result is the same as reflect.ValueOf(x):
// the fact that x was an interface value is forgotten.
func indirectInterface(v reflect.Value) reflect.Value {
	if v.Kind() != reflect.Interface {
		return v
	}
	if v.IsNil() {
		return reflect.Value{}
	}
	return v.Elem()
}

func reverseFunc(item reflect.Value) (<-chan any, error) {
	ch := make(chan any)
	var err error
	go func() {
		v := indirectInterface(item)
		switch item.Kind() {
		case reflect.Array, reflect.Slice, reflect.String:
			for i := v.Len(); i != 0; i-- {
				ch <- v.Index(i - 1).Interface()
			}
		default:
			err = fmt.Errorf("unsupported type, found %q", v.Kind().String())
		}

		close(ch)
	}()
	return ch, err
}
