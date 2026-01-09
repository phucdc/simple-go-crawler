package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

type Config struct {
	StartURL    string
	Proxy       string
	Cookie      string
	Session     string
	Token       string
	DontAccess  []string
	MaxDepth    int
	Concurrency int
	Verbose     bool
}

type FormOutput struct {
	URL        string   `json:"url"`
	Parameters []string `json:"parameters"`
	BodyParams []string `json:"body_params"`
	Method     string   `json:"method"`
}

type Form struct {
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Inputs  []FormInput `json:"inputs"`
	PageURL string      `json:"page_url"`
}

type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Required bool   `json:"required"`
}

type CrawlResult struct {
	seenForms map[string]bool
	mu        sync.Mutex
}

type Crawler struct {
	config     Config
	client     *http.Client
	result     *CrawlResult
	visited    map[string]bool
	visitedMu  sync.Mutex
	baseURL    *url.URL
	dontAccess []*regexp.Regexp
}

func main() {
	config := parseFlags()

	if config.StartURL == "" {
		fmt.Println("Error: URL is required")
		flag.Usage()
		os.Exit(1)
	}

	crawler, err := NewCrawler(config)
	if err != nil {
		fmt.Printf("Error initializing crawler: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting crawl of: %s\n", config.StartURL)
	if config.Proxy != "" {
		fmt.Printf("Using proxy: %s\n", config.Proxy)
	}

	crawler.Crawl(config.StartURL, 0)
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.StartURL, "url", "", "Target URL to crawl (required)")
	flag.StringVar(&config.Proxy, "proxy", "", "Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:1080)")
	flag.StringVar(&config.Cookie, "cookie", "", "Cookie header value")
	flag.StringVar(&config.Session, "session", "", "Session ID")
	flag.StringVar(&config.Token, "token", "", "Authorization token (Bearer)")
	flag.IntVar(&config.MaxDepth, "depth", 3, "Maximum crawl depth")
	flag.IntVar(&config.Concurrency, "concurrency", 5, "Number of concurrent requests")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")

	var dontAccessStr string
	flag.StringVar(&dontAccessStr, "dont-access", "", "Comma-separated list of URL patterns to skip (supports regex)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Form Crawler - A CLI tool to crawl websites and extract URLs and forms\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com -proxy http://127.0.0.1:8080\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com -cookie \"session=abc123\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com -token \"eyJhbGciOiJIUzI1NiIs...\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://example.com -dont-access \"logout,delete,/api/admin.*\"\n", os.Args[0])
	}

	flag.Parse()

	if dontAccessStr != "" {
		config.DontAccess = strings.Split(dontAccessStr, ",")
		for i, pattern := range config.DontAccess {
			config.DontAccess[i] = strings.TrimSpace(pattern)
		}
	}

	return config
}

func NewCrawler(config Config) (*Crawler, error) {
	baseURL, err := url.Parse(config.StartURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var dontAccessPatterns []*regexp.Regexp
	for _, pattern := range config.DontAccess {
		re, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Printf("Warning: Invalid regex pattern '%s', using as literal string\n", pattern)
			re = regexp.MustCompile(regexp.QuoteMeta(pattern))
		}
		dontAccessPatterns = append(dontAccessPatterns, re)
	}

	return &Crawler{
		config:  config,
		client:  client,
		baseURL: baseURL,
		result: &CrawlResult{
			seenForms: make(map[string]bool),
		},
		visited:    make(map[string]bool),
		dontAccess: dontAccessPatterns,
	}, nil
}

func (c *Crawler) shouldSkip(urlStr string) bool {
	for _, pattern := range c.dontAccess {
		if pattern.MatchString(urlStr) {
			if c.config.Verbose {
				fmt.Printf("[SKIP] %s (matches pattern: %s)\n", urlStr, pattern.String())
			}
			return true
		}
	}
	return false
}

func (c *Crawler) makeRequest(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	if c.config.Cookie != "" {
		req.Header.Set("Cookie", c.config.Cookie)
	}

	if c.config.Session != "" {
		existingCookie := req.Header.Get("Cookie")
		if existingCookie != "" {
			req.Header.Set("Cookie", existingCookie+"; PHPSESSID="+c.config.Session+"; session="+c.config.Session)
		} else {
			req.Header.Set("Cookie", "PHPSESSID="+c.config.Session+"; session="+c.config.Session)
		}
	}

	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	return c.client.Do(req)
}

func (c *Crawler) Crawl(targetURL string, depth int) {
	if depth > c.config.MaxDepth {
		return
	}

	c.visitedMu.Lock()
	if c.visited[targetURL] {
		c.visitedMu.Unlock()
		return
	}
	c.visited[targetURL] = true
	c.visitedMu.Unlock()

	if c.shouldSkip(targetURL) {
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	if parsedURL.Host != c.baseURL.Host {
		return
	}

	if c.config.Verbose {
		fmt.Printf("[CRAWL] Depth %d: %s\n", depth, targetURL)
	}

	resp, err := c.makeRequest(targetURL)
	if err != nil {
		if c.config.Verbose {
			fmt.Printf("[ERROR] %s: %v\n", targetURL, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if c.config.Verbose {
			fmt.Printf("[STATUS] %s: %d\n", targetURL, resp.StatusCode)
		}
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return
	}

	var newURLs []string

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		absoluteURL := c.resolveURL(targetURL, href)
		if absoluteURL == "" {
			return
		}

		c.visitedMu.Lock()
		if !c.visited[absoluteURL] {
			newURLs = append(newURLs, absoluteURL)
		}
		c.visitedMu.Unlock()
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		form := c.extractForm(s, targetURL)
		c.printFormIfNew(form)
	})

	for _, newURL := range newURLs {
		c.Crawl(newURL, depth+1)
	}
}

func (c *Crawler) resolveURL(base, href string) string {
	href = strings.TrimSpace(href)

	if strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "#") ||
		href == "" {
		return ""
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}

	refURL, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolvedURL := baseURL.ResolveReference(refURL)

	resolvedURL.Fragment = ""

	return resolvedURL.String()
}

func (c *Crawler) extractForm(s *goquery.Selection, pageURL string) Form {
	action, _ := s.Attr("action")
	method, _ := s.Attr("method")

	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	if action == "" {
		action = pageURL
	} else {
		resolved := c.resolveURL(pageURL, action)
		// If resolveURL returns empty (e.g., for "#" or "javascript:"), use pageURL
		if resolved == "" {
			action = pageURL
		} else {
			action = resolved
		}
	}

	var inputs []FormInput

	s.Find("input, textarea, select").Each(func(i int, input *goquery.Selection) {
		name, _ := input.Attr("name")
		inputType, _ := input.Attr("type")
		value, _ := input.Attr("value")
		_, required := input.Attr("required")

		tagName := goquery.NodeName(input)
		if tagName == "textarea" {
			inputType = "textarea"
			value = input.Text()
		} else if tagName == "select" {
			inputType = "select"
			var options []string
			input.Find("option").Each(func(j int, opt *goquery.Selection) {
				optVal, exists := opt.Attr("value")
				if exists {
					options = append(options, optVal)
				}
			})
			value = strings.Join(options, ", ")
		}

		if inputType == "" {
			inputType = "text"
		}

		// Only add inputs that have a name attribute
		if name != "" {
			inputs = append(inputs, FormInput{
				Name:     name,
				Type:     inputType,
				Value:    value,
				Required: required,
			})
		}
	})

	return Form{
		Action:  action,
		Method:  method,
		Inputs:  inputs,
		PageURL: pageURL,
	}
}

func (c *Crawler) printFormIfNew(form Form) {
	if form.Action == "" {
		return
	}

	// Parse the action URL to extract query parameters
	parsedURL, err := url.Parse(form.Action)
	if err != nil {
		return
	}

	// Get base URL without query string for deduplication key
	baseAction := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	key := form.Method + "|" + baseAction

	c.result.mu.Lock()
	if c.result.seenForms[key] {
		c.result.mu.Unlock()
		return
	}
	c.result.seenForms[key] = true
	c.result.mu.Unlock()

	// Extract query parameters from URL
	var urlParams []string
	for param := range parsedURL.Query() {
		urlParams = append(urlParams, param)
	}

	// Extract form input parameters
	var formParams []string
	for _, input := range form.Inputs {
		if input.Name != "" {
			formParams = append(formParams, input.Name)
		}
	}

	output := &FormOutput{
		URL:        baseAction,
		Method:     form.Method,
		Parameters: []string{},
		BodyParams: []string{},
	}

	// URL query params always go to Parameters
	if len(urlParams) > 0 {
		output.Parameters = append(output.Parameters, urlParams...)
	}

	// Form input params go to Parameters (GET) or BodyParams (POST)
	if form.Method == "GET" {
		if len(formParams) > 0 {
			output.Parameters = append(output.Parameters, formParams...)
		}
	} else {
		if len(formParams) > 0 {
			output.BodyParams = formParams
		}
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return
	}
	jsonStr := strings.ReplaceAll(string(jsonBytes), "\\u0026", "&")
	fmt.Println(jsonStr)
}
