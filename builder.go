package main

import (
	"bufio"
	"fmt"
	"gopkg.in/yaml.v2"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const baseDir = "./templates"
const assetsDir = baseDir + "/assets"
const imagesDir = assetsDir + "/images"
const scriptsDir = baseDir + "/scripts"
const configFile = "config.yaml"

type HoneypotConfig struct {
	ID				int	`yaml:"id"`
	Name			  string `yaml:"name"`
	CVE			   string `yaml:"cve"`
	Application	   string `yaml:"application"`
	Port			  int	`yaml:"port"`
	TemplateHTMLFile  string `yaml:"template_html_file"`
	DetectionEndpoint string `yaml:"detection_endpoint"`
	RequestRegex	  string `yaml:"request_regex"`
	DateCreated	   string `yaml:"date_created"`
	DateUpdated	   string `yaml:"date_updated"`
}

type Config struct {
	Honeypots []HoneypotConfig `yaml:"honeypots"`
}

func main() {
    reader := bufio.NewReader(os.Stdin)
    var config Config

    loadConfig(&config)

    fmt.Println("Enter honeypot configuration details:")
    honeypot := collectHoneypotConfig(reader)

    honeypot.ID = len(config.Honeypots) + 1

    config.Honeypots = append(config.Honeypots, honeypot)
    saveConfig(&config)

    fmt.Println("Enter the URL of the webpage to download:")
    webpageURL, _ := reader.ReadString('\n')
    webpageURL = strings.TrimSpace(webpageURL)

    if webpageURL == "" {
        fmt.Println("No URL provided, exiting.")
        return
    }

    fmt.Printf("Processing webpage: %s\n", webpageURL)
    savePage(webpageURL, honeypot.TemplateHTMLFile)
}

func collectHoneypotConfig(reader *bufio.Reader) HoneypotConfig {
	var honeypot HoneypotConfig

	honeypot.Name = promptForString(reader, "Name (mandatory): ", true)
	honeypot.CVE = promptForString(reader, "CVE (format CVE-YYYY-NNNNN, optional): ", false)
	honeypot.Application = promptForString(reader, "Application (mandatory): ", true)
	honeypot.Port = promptForPort(reader, "Port (1-65535, mandatory): ")
	honeypot.TemplateHTMLFile = promptForString(reader, "Template HTML file (output file name, mandatory): ", true)
	honeypot.DetectionEndpoint = promptForString(reader, "Detection endpoint (mandatory): ", true)
	honeypot.RequestRegex = promptForString(reader, "Request regex (mandatory, valid regex): ", true)

	currentDate := time.Now().Format("2006-01-02")
	honeypot.DateCreated = currentDate
	honeypot.DateUpdated = currentDate

	return honeypot
}

func promptForString(reader *bufio.Reader, prompt string, mandatory bool) string {
	for {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if mandatory && input == "" {
			fmt.Println("This field is mandatory. Please enter a value.")
			continue
		}

		if prompt == "CVE (format CVE-YYYY-NNNNN, optional): " && input != "" && !regexp.MustCompile(`CVE-\d{4}-\d{4,5}`).MatchString(input) {
			fmt.Println("Invalid CVE format. Please try again.")
			continue
		}

		if prompt == "Request regex (mandatory, valid regex): " {
			_, err := regexp.Compile(input)
			if err != nil {
				fmt.Println("Invalid regex. Please try again.")
				continue
			}
		}

		return input
	}
}

func promptForPort(reader *bufio.Reader, prompt string) int {
	for {
		input := promptForString(reader, prompt, true)
		port, err := strconv.Atoi(input)
		if err != nil || port < 1 || port > 65535 {
			fmt.Println("Invalid port. Please enter a number between 1 and 65535.")
			continue
		}
		return port
	}
}

func loadConfig(config *Config) {
	file, err := os.Open(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return // File does not exist, start with an empty config
		}
		panic(err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		panic(err)
	}
}

func saveConfig(config *Config) {
	file, err := os.Create(configFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	err = encoder.Encode(config)
	if err != nil {
		panic(err)
	}

	fmt.Println("Configuration saved successfully.")
}

func savePage(testurl, outputFileName string) {
	resp, err := http.Get(testurl)
	if err != nil {
		fmt.Println("Error fetching webpage:", err)
		return
	}
	defer resp.Body.Close()

	baseURL, err := url.Parse(testurl)
	if err != nil {
		fmt.Println("Error parsing base URL:", err)
		return
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		fmt.Println("Error parsing HTML:", err)
		return
	}

	processNodes(doc, baseURL)

	htmlFilePath := filepath.Join(baseDir, outputFileName)
	saveModifiedHTML(doc, htmlFilePath)
}

func processNodes(n *html.Node, baseURL *url.URL) {
	if n.Type == html.ElementNode && (n.Data == "img" || n.Data == "script") {
		for i, a := range n.Attr {
			if (n.Data == "img" && a.Key == "src") || (n.Data == "script" && a.Key == "src") {
				resourceURL, err := url.Parse(a.Val)
				if err != nil || (resourceURL.IsAbs() && resourceURL.Host != baseURL.Host) {
					fmt.Println("Invalid URL or external resource:", a.Val)
					continue
				}
				if !resourceURL.IsAbs() {
					resourceURL = baseURL.ResolveReference(resourceURL)
				}
				savePath := imagesDir
				if n.Data == "script" {
					savePath = scriptsDir
				}
				fileName := downloadResource(resourceURL.String(), savePath)
				if fileName != "" {
					n.Attr[i].Val = strings.Replace(savePath, baseDir, "", 1) + "/" + fileName
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		processNodes(c, baseURL)
	}
}

func downloadResource(resourceURL, savePath string) string {
	resp, err := http.Get(resourceURL)
	if err != nil {
		fmt.Println("Failed to download resource:", err)
		return ""
	}
	defer resp.Body.Close()

	err = os.MkdirAll(savePath, os.ModePerm)
	if err != nil {
		fmt.Println("Failed to create directory:", err)
		return ""
	}

	path := resp.Request.URL.Path
	fileName := filepath.Base(path)
	filePath := filepath.Join(savePath, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Failed to create file:", err)
		return ""
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Println("Failed to save resource:", err)
		return ""
	}

	return fileName
}

func saveModifiedHTML(doc *html.Node, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating the HTML file:", err)
		return
	}
	defer file.Close()

	err = html.Render(file, doc)
	if err != nil {
		fmt.Println("Error writing the modified HTML:", err)
		return
	}
	fmt.Println("Modified HTML saved successfully.")
}
