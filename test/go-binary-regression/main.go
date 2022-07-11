package main

import (
	"fmt"
	"net/http"

	"github.com/ghodss/yaml"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
)

type Person struct {
	Name string `json:"name"` // Affects YAML field names too.
	Age  int    `json:"age"`
}

func main() {
	p := Person{"John", 30}
	y, _ := yaml.Marshal(p)
	fmt.Println(y)
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	fmt.Println(rdb)
	r := mux.NewRouter()
	http.Handle("/", r)
}
