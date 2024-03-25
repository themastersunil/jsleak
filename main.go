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
                "algolia_admin_key_1" : `algolia[_-]?admin[_-]?key[_-]?1(=| =|:| :)`,
                "Algoliaadminkey - 2" : `(?:algolia).{0,40}\\b([a-zA-Z0-9]{32})\\b`,
                "algolia_admin_key_2" : `algolia[_-]?admin[_-]?key[_-]?2(=| =|:| :)`,
                "algolia_admin_key_mcm" : `algolia[_-]?admin[_-]?key[_-]?mcm(=| =|:| :)`,
                "algolia_api_key" : `algolia[_-]?api[_-]?key(=| =|:| :)`,
                "Algolia API Key" : `(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "algolia_api_key_mcm" : `algolia[_-]?api[_-]?key[_-]?mcm(=| =|:| :)`,
                "algolia_api_key_search" : `algolia[_-]?api[_-]?key[_-]?search(=| =|:| :)`,
                "algolia_search_api_key" : `algolia[_-]?search[_-]?api[_-]?key(=| =|:| :)`,
                "algolia_search_key_1" : `algolia[_-]?search[_-]?key[_-]?1(=| =|:| :)`,
                "algolia_search_key" : `algolia[_-]?search[_-]?key(=| =|:| :)`,
                "Amplitudeapikey" : `(?:amplitude).{0,40}\\b([a-f0-9]{32})`,
                "Asana Client ID" : `(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Asana Client Secret" : `(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Asanaoauth" : `(?:asana).{0,40}\\b([a-z\\/:0-9]{51})\\b`,
                "Asanapersonalaccesstoken" : `(?:asana).{0,40}\\b([0-9]{1,}\\/[0-9]{16,}:[A-Za-z0-9]{32,})\\b`,
                "author_npm_api_key" : `author[_-]?npm[_-]?api[_-]?key(=| =|:| :)`,
                "Bitlyaccesstoken" : `(?:bitly).{0,40}\\b([a-zA-Z-0-9]{40})\\b`,
                "Buildkite" : `(?:buildkite).{0,40}\\b([a-z0-9]{40})\\b`,
                "bundlesize_github_token" : `bundlesize[_-]?github[_-]?token(=| =|:| :)`,
                "Buttercms" : `(?:buttercms).{0,40}\\b([a-z0-9]{40})\\b`,
                "Calendlyapikey" : `(?:calendly).{0,40}\\b([a-zA-Z-0-9]{20}.[a-zA-Z-0-9]{171}.[a-zA-Z-0-9_]{43})\\b`,
                "Circleci" : `(?:circle).{0,40}([a-fA-F0-9]{40})`,
                "cloudflare_api_key" : `cloudflare[_-]?api[_-]?key(=| =|:| :)`,
                "Cloudflareapitoken" : `(?:cloudflare).{0,40}\\b([A-Za-z0-9_-]{40})\\b`,
                "cloudflare_auth_email" : `cloudflare[_-]?auth[_-]?email(=| =|:| :)`,
                "cloudflare_auth_key" : `cloudflare[_-]?auth[_-]?key(=| =|:| :)`,
                "Cloudflarecakey" : `(?:cloudflare).{0,40}\\b(v[A-Za-z0-9._-]{173,})\\b`,
                "cloudflare_email" : `cloudflare[_-]?email(=| =|:| :)`,
                "Cloudflareglobalapikey - 1" : `\\b([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)\\b`,
                "Cloudflareglobalapikey - 2" : `(?:cloudflare).{0,40}([A-Za-z0-9_-]{37})`,
                "contentful_access_token" : `contentful[_-]?access[_-]?token(=| =|:| :)`,
                "contentful_cma_test_token" : `contentful[_-]?cma[_-]?test[_-]?token(=| =|:| :)`,
                "Contentful delivery API token" : `(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "contentful_integration_management_token" : `contentful[_-]?integration[_-]?management[_-]?token(=| =|:| :)`,
                "Contentfulpersonalaccesstoken" : `\\b([CFPAT\\-a-zA-Z-0-9]{49})\\b`,
                "contentful_php_management_test_token" : `contentful[_-]?php[_-]?management[_-]?test[_-]?token(=| =|:| :)`,
                "contentful_test_org_cma_token" : `contentful[_-]?test[_-]?org[_-]?cma[_-]?token(=| =|:| :)`,
                "contentful_v2_access_token" : `contentful[_-]?v2[_-]?access[_-]?token(=| =|:| :)`,
                "danger_github_api_token" : `danger[_-]?github[_-]?api[_-]?token(=| =|:| :)`,
                "Datadog Access Token" : `(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "datadog_api_key" : `datadog[_-]?api[_-]?key(=| =|:| :)`,
                "datadog_app_key" : `datadog[_-]?app[_-]?key(=| =|:| :)`,
                "Datadogtoken - 1" : `(?:datadog).{0,40}\\b([a-zA-Z-0-9]{32})\\b`,
                "Datadogtoken - 2" : `(?:datadog).{0,40}\\b([a-zA-Z-0-9]{40})\\b`,
                "ddgc_github_token" : `ddgc[_-]?github[_-]?token(=| =|:| :)`,
                "Delighted" : `(?:delighted).{0,40}\\b([a-z0-9A-Z]{32})\\b`,
                "Dropbox API secret" : `(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Dropbox" : `\\b(sl\\.[A-Za-z0-9\\-\\_]{130,140})\\b`,
                "Dropbox long lived API token" : `(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "dropbox_oauth_bearer" : `dropbox[_-]?oauth[_-]?bearer(=| =|:| :)`,
                "Dropbox short lived API token" : `(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(sl\.[a-z0-9\-=_]{135})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "droplet_travis_password" : `droplet[_-]?travis[_-]?password(=| =|:| :)`,
                "env_github_oauth_token" : `env[_-]?github[_-]?oauth[_-]?token(=| =|:| :)`,
                "env_heroku_api_key" : `env[_-]?heroku[_-]?api[_-]?key(=| =|:| :)`,
                "facebook_access_token" : `(EAACEdEose0cBA[0-9A-Za-z]+)`,
                "Facebook Access Token" : `EAACEdEose0cBA[0-9A-Za-z]+`,
                "firebase_api_token" : `firebase[_-]?api[_-]?token(=| =|:| :)`,
                "firebase_key" : `firebase[_-]?key(=| =|:| :)`,
                "firebase_token" : `firebase[_-]?token(=| =|:| :)`,
                "Foursquare" : `(?:foursquare).{0,40}\\b([0-9A-Z]{48})\\b`,
                "Github - 2" : `\\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\\b)`,
                "github_access_token - 1" : `github[_-]?access[_-]?token(=| =|:| :)`,
                "github_access_token - 2" : `[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*`,
                "github_api_key" : `github[_-]?api[_-]?key(=| =|:| :)`,
                "github_api_token" : `github[_-]?api[_-]?token(=| =|:| :)`,
                "Githubapp - 1" : `(?:github).{0,40}\\b([0-9]{6})\\b`,
                "Githubapp - 2" : `(?:github).{0,40}(-----BEGIN RSA PRIVATE KEY-----\\s[A-Za-z0-9+\\/\\s]*\\s-----END RSA PRIVATE KEY-----)`,
                "Github App Token" : `(ghu|ghs)_[0-9a-zA-Z]{36}`,
                "GitHub App Token" : `(ghu|ghs)_[0-9a-zA-Z]{36}`,
                "github_auth" : `github[_-]?auth(=| =|:| :)`,
                "github_auth_token" : `github[_-]?auth[_-]?token(=| =|:| :)`,
                "github_client_secret" : `github[_-]?client[_-]?secret(=| =|:| :)`,
                "github_deploy_hb_doc_pass" : `github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass(=| =|:| :)`,
                "github_deployment_token" : `github[_-]?deployment[_-]?token(=| =|:| :)`,
                "GitHub Fine-Grained Personal Access Token" : `github_pat_[0-9a-zA-Z_]{82}`,
                "github_hunter_token" : `github[_-]?hunter[_-]?token(=| =|:| :)`,
                "github_hunter_username" : `github[_-]?hunter[_-]?username(=| =|:| :)`,
                "github_key" : `github[_-]?key(=| =|:| :)`,
                "Github OAuth Access Token" : `gho_[0-9a-zA-Z]{36}`,
                "GitHub OAuth Access Token" : `gho_[0-9a-zA-Z]{36}`,
                "github_oauth" : `github[_-]?oauth(=| =|:| :)`,
                "github_oauth_token" : `github[_-]?oauth[_-]?token(=| =|:| :)`,
                "Github_old" : `(?:github)[^\\.].{0,40}[ =:'\"]+([a-f0-9]{40})\\b`,
                "github_password" : `github[_-]?password(=| =|:| :)`,
                "Github Personal Access Token" : `ghp_[0-9a-zA-Z]{36}`,
                "GitHub Personal Access Token" : `ghp_[0-9a-zA-Z]{36}`,
                "github_pwd" : `github[_-]?pwd(=| =|:| :)`,
                "GitHub Refresh Token" : `ghr_[0-9a-zA-Z]{36}`,
                "Github Refresh Token" : `ghr_[0-9a-zA-Z]{76}`,
                "github_release_token" : `github[_-]?release[_-]?token(=| =|:| :)`,
                "github_repo" : `github[_-]?repo(=| =|:| :)`,
                "github_token" : `github[_-]?token(=| =|:| :)`,
                "github_tokens" : `github[_-]?tokens(=| =|:| :)`,
                "GitLab Personal Access Token" : `glpat-[0-9a-zA-Z\-\_]{20}`,
                "GitLab Pipeline Trigger Token" : `glptt-[0-9a-f]{40}`,
                "GitLab Runner Registration Token" : `GR1348941[0-9a-zA-Z\-\_]{20}`,
                "Google API Key" : `AIza[0-9a-z-_]{35}`,
                "gren_github_token" : `gren[_-]?github[_-]?token(=| =|:| :)`,
                "heroku_api_key_api_key" : `([h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})`,
                "heroku_api_key" : `heroku[_-]?api[_-]?key(=| =|:| :)`,
                "Heroku API Key" : `(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "heroku_email" : `heroku[_-]?email(=| =|:| :)`,
                "Heroku" : `(?:heroku).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b`,
                "heroku_token" : `heroku[_-]?token(=| =|:| :)`,
                "homebrew_github_api_token" : `homebrew[_-]?github[_-]?api[_-]?token(=| =|:| :)`,
                "Hubspotapikey" : `(?:hubspot).{0,40}\\b([A-Za-z0-9]{8}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{4}\\-[A-Za-z0-9]{12})\\b`,
                "HubSpot API Token" : `(?i)(?:hubspot)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Instagram oauth" : `[0-9a-fA-F]{7}\\.[0-9a-fA-F]{32}`,
                "Ipstack" : `(?:ipstack).{0,40}\\b([a-fA-f0-9]{32})\\b`,
                "Jumpcloud" : `(?:jumpcloud).{0,40}\\b([a-zA-Z0-9]{40})\\b`,
                "Keenio - 1" : `(?:keen).{0,40}\\b([0-9a-z]{24})\\b`,
                "Keenio - 2" : `(?:keen).{0,40}\\b([0-9A-Z]{64})\\b`,
                "Lokalisetoken" : `(?:lokalise).{0,40}\\b([a-z0-9]{40})\\b`,
                "Mailgun - 2" : `(?:mailgun).{0,40}\\b([a-zA-Z-0-9]{72})\\b`,
                "Mailgun API Key - 1" : `key-[0-9a-zA-Z]{32}`,
                "Mailgun API key - 2" : `(mailgun|mg)[0-9a-z]{32}`,
                "mailgun_api_key" : `mailgun[_-]?api[_-]?key(=| =|:| :)`,
                "mailgun_apikey" : `mailgun[_-]?apikey(=| =|:| :)`,
                "mailgun" : `(key-[0-9a-f]{32})`,
                "mailgun_password" : `mailgun[_-]?password(=| =|:| :)`,
                "Mailgun private API token" : `(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(key-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "mailgun_priv_key" : `mailgun[_-]?priv[_-]?key(=| =|:| :)`,
                "mailgun_pub_apikey" : `mailgun[_-]?pub[_-]?apikey(=| =|:| :)`,
                "mailgun_pub_key" : `mailgun[_-]?pub[_-]?key(=| =|:| :)`,
                "Mailgun public validation key" : `(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pubkey-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "mailgun_secret_api_key" : `mailgun[_-]?secret[_-]?api[_-]?key(=| =|:| :)`,
                "Mailgun webhook signing key" : `(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Mapbox - 1" : `\\b(sk\\.[a-zA-Z-0-9\\.]{80,240})\\b`,
                "mapbox_access_token" : `mapbox[_-]?access[_-]?token(=| =|:| :)`,
                "mapboxaccesstoken" : `mapboxaccesstoken(=| =|:| :)`,
                "MapBox API token" : `(?i)(?:mapbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "mapbox_api_token" : `mapbox[_-]?api[_-]?token(=| =|:| :)`,
                "mapbox_aws_access_key_id" : `mapbox[_-]?aws[_-]?access[_-]?key[_-]?id(=| =|:| :)`,
                "mapbox_aws_secret_access_key" : `mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key(=| =|:| :)`,
                "Newrelic Admin API Key" : `NRAA-[a-f0-9]{27}`,
                "New Relic ingest browser API token" : `(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRJS-[a-f0-9]{19})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Newrelic Insights API Key" : `NRI(?:I|Q)-[A-Za-z0-9\\-_]{32}`,
                "Newrelicpersonalapikey" : `(?:newrelic).{0,40}\\b([A-Za-z0-9_\\.]{4}-[A-Za-z0-9_\\.]{42})\\b`,
                "Newrelic REST API Key" : `NRRA-[a-f0-9]{42}`,
                "Newrelic Synthetics Location Key" : `NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}`,
                "New Relic user API ID" : `(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "New Relic user API Key" : `(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "node_pre_gyp_github_token" : `node[_-]?pre[_-]?gyp[_-]?github[_-]?token(=| =|:| :)`,
                "npm access token" : `(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "npm_api_key" : `npm[_-]?api[_-]?key(=| =|:| :)`,
                "npm_api_token" : `npm[_-]?api[_-]?token(=| =|:| :)`,
                "npm_auth_token" : `npm[_-]?auth[_-]?token(=| =|:| :)`,
                "npm_email" : `npm[_-]?email(=| =|:| :)`,
                "npm_password" : `npm[_-]?password(=| =|:| :)`,
                "npm_secret_key" : `npm[_-]?secret[_-]?key(=| =|:| :)`,
                "npm_token - 1" : `npm[_-]?token(=| =|:| :)`,
                "Pagerdutyapikey" : `(?:pagerduty).{0,40}\\b([a-z]{1}\\+[a-zA-Z]{9}\\-[a-z]{2}\\-[a-z0-9]{5})\\b`,
                "pagerduty_apikey" : `pagerduty[_-]?apikey(=| =|:| :)`,
                "passwordtravis" : `passwordtravis(=| =|:| :)`,
                "Pivotaltracker" : `(?:pivotal).{0,40}([a-z0-9]{32})`,
                "salesforce_bulk_test_password" : `salesforce[_-]?bulk[_-]?test[_-]?password(=| =|:| :)`,
                "salesforce_bulk_test_security_token" : `salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token(=| =|:| :)`,
                "spotify_api_access_token" : `spotify[_-]?api[_-]?access[_-]?token(=| =|:| :)`,
                "spotify_api_client_secret" : `spotify[_-]?api[_-]?client[_-]?secret(=| =|:| :)`,
                "Spotifykey - 1" : `(?:key|secret).{0,40}\\b([A-Za-z0-9]{32})\\b`,
                "Spotifykey - 2" : `(?:id).{0,40}\\b([A-Za-z0-9]{32})\\b`,
                "Square Access Token" : `(?i)\b(sq0atp-[0-9A-Za-z\-_]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Square access token" : `sq0atp-[0-9A-Za-z\\-_]{22}`,
                "Square API Key" : `sq0(atp|csp)-[0-9a-z-_]{22,43}`,
                "Squareapp - 1" : `[\\w\\-]*sq0i[a-z]{2}-[0-9A-Za-z\\-_]{22,43}`,
                "Squareapp - 2" : `[\\w\\-]*sq0c[a-z]{2}-[0-9A-Za-z\\-_]{40,50}`,
                "square_app_secret" : `(sq0[a-z]{3}-[0-9A-Za-z-_]{20,50})`,
                "Square OAuth Secret" : `sq0csp-[0-9A-Za-z\\-_]{43}`,
                "square_reader_sdk_repository_password" : `square[_-]?reader[_-]?sdk[_-]?repository[_-]?password(=| =|:| :)`,
                "Squarespace Access Token" : `(?i)(?:squarespace)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Squarespace" : `(?:squarespace).{0,40}\\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b`,
                "Square" : `(?:square).{0,40}(EAAA[a-zA-Z0-9\\-\\+\\=]{60})`,
                "Squareup" : `\\b(sq0idp-[0-9A-Za-z]{22})\\b`,
                "Stripe API Key - 1" : `sk_live_[0-9a-zA-Z]{24}`,
                "Stripe API key - 2" : `stripe[sr]k_live_[0-9a-zA-Z]{24}`,
                "Stripe API key - 3" : `stripe[sk|rk]_live_[0-9a-zA-Z]{24}`,
                "Stripe" : `(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`,
                "stripe_private" : `stripe[_-]?private(=| =|:| :)`,
                "Stripe Public Live Key" : `pk_live_[0-9a-z]{24}`,
                "stripe_public" : `stripe[_-]?public(=| =|:| :)`,
                "Stripe Public Test Key" : `pk_test_[0-9a-z]{24}`,
                "Stripe Restriced Key" : `rk_(?:live|test)_[0-9a-zA-Z]{24}`,
                "Stripe Restricted API Key" : `rk_live_[0-9a-zA-Z]{24}`,
                "stripe_restricted_api" : `(rk_live_[0-9a-zA-Z]{24,34})`,
                "Stripe Secret Key" : `sk_(?:live|test)_[0-9a-zA-Z]{24}`,
                "Stripe Secret Live Key" : `(sk|rk)_live_[0-9a-z]{24}`,
                "Stripe Secret Test Key" : `(sk|rk)_test_[0-9a-z]{24}`,
                "stripe_standard_api" : `(sk_live_[0-9a-zA-Z]{24,34})`,
                "Telegram Bot API Key" : `[0-9]+:AA[0-9A-Za-z\\-_]{33}`,
                "Telegram Bot API Token" : `(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])`,
                "Telegrambottoken" : `(?:telegram).{0,40}\\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\\b`,
                "Telegram Secret" : `d{5,}:A[0-9a-z_-]{34,34}`,
                "test_github_token" : `test[_-]?github[_-]?token(=| =|:| :)`,
                "travis_access_token" : `travis[_-]?access[_-]?token(=| =|:| :)`,
                "travis_api_token" : `travis[_-]?api[_-]?token(=| =|:| :)`,
                "travis_branch" : `travis[_-]?branch(=| =|:| :)`,
                "Travis CI Access Token" : `(?i)(?:travis)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Travisci" : `(?:travis).{0,40}\\b([a-zA-Z0-9A-Z_]{22})\\b`,
                "travis_com_token" : `travis[_-]?com[_-]?token(=| =|:| :)`,
                "travis_e2e_token" : `travis[_-]?e2e[_-]?token(=| =|:| :)`,
                "travis_gh_token" : `travis[_-]?gh[_-]?token(=| =|:| :)`,
                "travis_pull_request" : `travis[_-]?pull[_-]?request(=| =|:| :)`,
                "travis_secure_env_vars" : `travis[_-]?secure[_-]?env[_-]?vars(=| =|:| :)`,
                "travis_token" : `travis[_-]?token(=| =|:| :)`,
                "Twilio - 1" : `\\bAC[0-9a-f]{32}\\b`,
                "Twilio API Key" : `SK[0-9a-fA-F]{32}`,
                "twilio_api_key" : `twilio[_-]?api[_-]?key(=| =|:| :)`,
                "twilio_api_secret" : `twilio[_-]?api[_-]?secret(=| =|:| :)`,
                "twilio_chat_account_api_service" : `twilio[_-]?chat[_-]?account[_-]?api[_-]?service(=| =|:| :)`,
                "twilio_configuration_sid" : `twilio[_-]?configuration[_-]?sid(=| =|:| :)`,
                "twilio_sid" : `twilio[_-]?sid(=| =|:| :)`,
                "twilio_token" : `twilio[_-]?token(=| =|:| :)`,
        	"Twitter Access Secret" : `(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{45})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Twitter Access Token" : `(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Twitter API Key" : `(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Twitter API Secret" : `(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Twitter Bearer Token" : `(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "Twitter Client ID" : `twitter[0-9a-z]{18,25}`,
                "twitter_consumer_key" : `twitter[_-]?consumer[_-]?key(=| =|:| :)`,
                "twitter_consumer_secret" : `twitter[_-]?consumer[_-]?secret(=| =|:| :)`,
                "twitteroauthaccesssecret" : `twitteroauthaccesssecret(=| =|:| :)`,
                "twitteroauthaccesstoken" : `twitteroauthaccesstoken(=| =|:| :)`,
                "Twitter Secret Key" : `twitter[0-9a-z]{35,44}`,
                "usertravis" : `usertravis(=| =|:| :)`,
                "vip_github_build_repo_deploy_key" : `vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key(=| =|:| :)`,
                "vip_github_deploy_key_pass" : `vip[_-]?github[_-]?deploy[_-]?key[_-]?pass(=| =|:| :)`,
                "vip_github_deploy_key" : `vip[_-]?github[_-]?deploy[_-]?key(=| =|:| :)`,
                "wakatime_api_key" : `wakatime[_-]?api[_-]?key(=| =|:| :)`,
                "Zapierwebhook" : `(https:\\/\\/hooks.zapier.com\\/hooks\\/catch\\/[A-Za-z0-9\\/]{16})`,
                "Zapier Webhook" : `https://(?:www.)?hooks\\.zapier\\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/`,
                "Zendeskapi - 1" : `\\b([a-zA-Z-0-9]{3,16}\\.zendesk\\.com)\\b`,
                "Zendeskapi - 2" : `\\b([a-zA-Z-0-9-]{5,16}\\@[a-zA-Z-0-9]{4,16}\\.[a-zA-Z-0-9]{3,6})\\b`,
                "Zendeskapi - 3" : `(?:zendesk).{0,40}([A-Za-z0-9_-]{40})`,
                "Zendesk Secret Key" : `(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
                "zendesk_travis_github" : `zendesk[_-]?travis[_-]?github(=| =|:| :)`,
		"JSON Web Token" : `(?i)\b(ey[0-9a-z]{30,34}\.ey[0-9a-z-\/_]{30,500}\.[0-9a-zA-Z-\/_]{10,200}={0,2})(?:['|\"|\n|\r|\s|\x60|;]|$)`,
		"Private Key" : `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY( BLOCK)?----`,
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
