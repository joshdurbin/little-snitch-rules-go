package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"
)

func main() {

	ticker := time.NewTicker(6 * time.Hour)
	var mutex = &sync.RWMutex{}
	var gzippedLittleSnitchConfigJsonBytes = &bytes.Buffer{}

	loadProcessCompress(*mutex, gzippedLittleSnitchConfigJsonBytes)

	go func() {
		for {
			select {
			case <-ticker.C:
				loadProcessCompress(*mutex, gzippedLittleSnitchConfigJsonBytes)
			}
		}
	}()

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		//writer.Header().Set("Content-Encoding", "gzip")
		writer.Header().Set("Transfer-Encoding", "gzip")
		mutex.RLock()
		writer.Write(gzippedLittleSnitchConfigJsonBytes.Bytes())
		mutex.RUnlock()
	})

	//http.ListenAndServe(":9999", nil)
	http.ListenAndServeTLS(":9999", "cert.pem", "key.pem", nil)
}

func loadProcessCompress(mutex sync.RWMutex, buffer *bytes.Buffer) {

	log.Println("Loading remote hosts file...")
	response, _ := http.Get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
	defer response.Body.Close()

	regex, _ := regexp.Compile("^0.0.0.0 ([^#]*)(#.*)?")

	scanner := bufio.NewScanner(response.Body)
	domains := make([]string, 0)

	for scanner.Scan() {

		line := scanner.Text()
		matchGroups := regex.FindStringSubmatch(line)
		if len(matchGroups) != 0 {
			domains = append(domains, matchGroups[1])
		}
	}

	domainAsRules := make([]LittleSnitchRule, len(domains))
	for index, domain := range domains {
		domainAsRules[index] = LittleSnitchRule{
			Action:      "deny",
			Process:     "any",
			RemoteHosts: domain,
			Direction:   "outgoing",
		}
	}

	littleSnitchConfig := LittleSnitch{
		Name:        "",
		Description: "",
		Rules:       domainAsRules,
	}

	log.Printf("Processed %v for JSON serialization", len(domainAsRules))

	littleSnitchConfigJsonBytes, _ := json.Marshal(littleSnitchConfig)

	mutex.Lock()
	buffer.Reset()
	gz := gzip.NewWriter(buffer)
	_, _ = gz.Write(littleSnitchConfigJsonBytes)
	gz.Close()
	mutex.Unlock()
	log.Printf("In memory lsrules are %v bytes, compressed, %.2f the original size", buffer.Len(), float64(buffer.Len()) / float64(len(littleSnitchConfigJsonBytes)))
}

type LittleSnitch struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Rules       []LittleSnitchRule `json:"rules"`
}

type LittleSnitchRule struct {
	Action      string `json:"action"`
	Process     string `json:"process"`
	RemoteHosts string `json:"remote-hosts"`
	Direction   string `json:"direction"`
}
