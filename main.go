package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
	"regexp"
	"os"
	"bufio"
	"sync"
	"flag"
	"net/url"
	"strings"
)

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	},
}

func request(fullurl string, statusCode bool) string {
	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	req.Header.Add("User-Agent", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()
	 if statusCode && resp.StatusCode != 404 {
	 	fmt.Printf("[Linkfinder] %s : %d\n", fullurl,  resp.StatusCode)
	 }

	var bodyString string
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		bodyString = string(bodyBytes)
	}
	return bodyString
}

func regexGrep(content string, Burl string) {
	regex_map := map[string]string{
		"Algoliaadminkey - 1" : `(?:algolia).{0,40}\\b([A-Z0-9]{10})\\b`,
		"Algoliaadminkey - 2" : `(?:algolia).{0,40}\\b([a-zA-Z0-9]{32})\\b`,
		"Algolia API Key" : `(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`,	
		"algolia_admin_key_1" : `algolia[_-]?admin[_-]?key[_-]?1(=| =|:| :)`,
		"algolia_admin_key_2" : `algolia[_-]?admin[_-]?key[_-]?2(=| =|:| :)`,
		"algolia_admin_key_mcm" : `algolia[_-]?admin[_-]?key[_-]?mcm(=| =|:| :)`,
		"algolia_api_key" : `algolia[_-]?api[_-]?key(=| =|:| :)`,
		"algolia_api_key_mcm" : `algolia[_-]?api[_-]?key[_-]?mcm(=| =|:| :)`,
		"algolia_api_key_search" : `algolia[_-]?api[_-]?key[_-]?search(=| =|:| :)`,
		"algolia_search_api_key" : `algolia[_-]?search[_-]?api[_-]?key(=| =|:| :)`,
		"algolia_search_key" : `algolia[_-]?search[_-]?key(=| =|:| :)`,
		"algolia_search_key_1" : `algolia[_-]?search[_-]?key[_-]?1(=| =|:| :)`,
	}

	for key, element := range regex_map {
		r := regexp.MustCompile(element)
		matches := r.FindAllString(content, -1)
		for _, v := range matches {
			fmt.Println("[+] Found " + "[" + key + "]" + "	[" + v + "]" + "	[" + Burl + "]")
		}
	}


}

func linkFinder(content, baseURL string, completeURL, statusCode bool) {
    linkRegex := `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`

    r := regexp.MustCompile(linkRegex)
    matches := r.FindAllString(content, -1)

    base, err := url.Parse(baseURL)
    if err != nil {
        fmt.Println("")
    }

    for _, v := range matches {
        cleanedMatch := strings.Trim(v, `"'`)
        link, err := url.Parse(cleanedMatch)
        if err != nil {
            continue
        }
        if completeURL {
            link = base.ResolveReference(link)
        }
        if statusCode {
            request(link.String(), true)
        } else {
            fmt.Printf("[+] Found link: [%s] in [%s] \n", link.String(),  base.String())
        }
    }
}


func main() {
	var concurrency int
	var enableLinkFinder, completeURL, checkStatus, enableSecretFinder bool
	flag.BoolVar(&enableLinkFinder, "l", false, "Enable linkFinder")
	flag.BoolVar(&completeURL, "e", false, "Complete Scope Url or not")
	flag.BoolVar(&checkStatus, "k", false, "Check status or not")
	flag.BoolVar(&enableSecretFinder, "s", false, "Enable secretFinder")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.Parse()
	urls := make(chan string, 10)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls <- sc.Text()
		}
		close(urls)
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}()

	wg := sync.WaitGroup{}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for vUrl := range urls {
				res := request(vUrl, false)
				
				if enableSecretFinder {
					regexGrep(res, vUrl)
				}
				if enableLinkFinder {
					linkFinder(res, vUrl, false, false)
				}
				if completeURL {
					linkFinder(res, vUrl, true, false)
				}
				if checkStatus {
					linkFinder(res, vUrl, true, true)
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
