package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
    "github.com/queencitycyber/parkeddomains/version"
)

var (
    minThreadingInputSize = 20
    threads               = flag.Int("threads", 10, "Number of threads to use. Default is 10")
    insecure              = flag.Bool("insecure", true, "Allow insecure server connections when using SSL")
    verbose               = flag.Bool("verbose", false, "Enable verbose mode and show error messages")
    timeout               = flag.Int("timeout", 25, "Maximum timeout of each request. Default is 25 seconds.")
    flagURL               = flag.String("u", "", "The single domain or HTTP URL to scan")
    flagFile              = flag.String("f", "", "The source file containing a list of domains/URLs to scan")
    flagOutput            = flag.String("o", "", "Output file to write deduplicated results")

    parkedContentRegex = regexp.MustCompile(`buy this domain|parked free|godaddy|is for sale|domain parking|renew now|this domain|namecheap|buy now for|hugedomains|is owned and listed by|sav.com|searchvity.com|domain for sale|register4less|aplus.net|related searches|related links|search ads|domain expert|united domains|domian name has been registered|this domain may be for sale|domain name is available for sale|premium domain|this domain name|this domain has expired|domainpage.io|sedoparking.com|parking-lander`)
)

type Result struct {
    URL string `json:"url"`
}

func isContentParked(content string) bool {
    return parkedContentRegex.MatchString(content)
}

func followURL(urlStr string) (string, error) {
    client := &http.Client{
        Timeout: time.Duration(*timeout) * time.Second,
    }

    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return "", err
    }

    req.Header.Set("User-Agent", "Mozilla/5.0 Gecko/18.1 Firefox/18.1")

    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    location := resp.Header.Get("Location")
    if location != "" {
        targetDomain := getDomainFromURL(urlStr)
        redirectDomain := getDomainFromURL(location)

        if targetDomain == redirectDomain || "www."+targetDomain == redirectDomain {
            return followURL(location)
        }
    }

    scanner := bufio.NewScanner(resp.Body)
    var body strings.Builder
    for scanner.Scan() {
        body.WriteString(scanner.Text())
    }

    return body.String(), nil
}

func getDomainFromURL(urlStr string) string {
    parsedURL, _ := url.Parse(urlStr)
    return parsedURL.Host
}

func handleURL(urlStr string, wg *sync.WaitGroup, results chan<- string) {
    defer wg.Done()

    urlStr = strings.TrimSpace(urlStr)
    if !strings.HasPrefix(urlStr, "http") {
        urlStr = "http://" + urlStr
    }

    body, err := followURL(urlStr)
    if err != nil {
        if *verbose {
            fmt.Printf("Error loading URL: %s - %s\n", urlStr, err)
        }
        return
    }

    if isContentParked(body) {
        results <- urlStr
    }
}

func main() {

    versionFlag := flag.Bool("version", false, "Version")
    flag.Parse()
    if *versionFlag {
        fmt.Println("Build Date:", version.BuildDate)
        fmt.Println("Git Commit:", version.GitCommit)
        fmt.Println("Version:", version.Version)
        fmt.Println("Go Version:", version.GoVersion)
        fmt.Println("OS / Arch:", version.OsArch)
        return
    }    

    if *flagURL == "" && *flagFile == "" {
        fmt.Println("Please provide either a URL with the -u flag or a file with the -f flag.")
        return
    }

    var urls []string

    if *flagURL != "" {
        urls = append(urls, *flagURL)
    } else if *flagFile != "" {
        file, err := os.Open(*flagFile)
        if err != nil {
            fmt.Println("Error opening file:", err)
            return
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            urls = append(urls, scanner.Text())
        }

        if err := scanner.Err(); err != nil {
            fmt.Println("Error reading file:", err)
            return
        }
    }

    results := make(chan string)
    var wg sync.WaitGroup

    for i := 0; i < *threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()

            for _, url := range urls {
                handleURL(url, &wg, results)
            }
        }()
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    uniqueResults := make(map[string]bool)
    var parkedDomains []string
    for result := range results {
        if !uniqueResults[result] {
            uniqueResults[result] = true
            parkedDomains = append(parkedDomains, result)
        }
    }

    output, err := json.Marshal(parkedDomains)
    if err != nil {
        fmt.Println("Error marshalling JSON:", err)
        return
    }

    fmt.Println(string(output))

    if *flagOutput != "" {
        outputFile, err := os.Create(*flagOutput)
        if err != nil {
            fmt.Println("Error creating output file:", err)
            return
        }
        defer outputFile.Close()

        if _, err := outputFile.Write(output); err != nil {
            fmt.Println("Error writing to output file:", err)
            return
        }
    }
}
