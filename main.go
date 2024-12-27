package main

import (
	"encoding/json" // 导入json包
	"fmt"
	"github.com/projectdiscovery/goflags"
	"katana/utils"
	"math"
	"net/url"
	"os" // 导入os包
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// Result 结果结构体
type Result struct {
	URLs      []string `json:"url"`
	LoginURLs []string `json:"login_url"`
	Count     int      `json:"count"` // 添加计数器字段
}

// CrawlResult 爬虫结果
type CrawlResult struct {
	sync.RWMutex
	Results map[string]*Result
}

// 判断是否为登录页面的函数
func isLoginPage(body string) bool {
	bodyLower := strings.ToLower(body)
	// 检查页面内容是否同时包含 <form> 和 type="password">
	return strings.Contains(bodyLower, "<form") && strings.Contains(bodyLower, "type=\"password\"")
}

func main() {
	crawlResult := &CrawlResult{
		Results: make(map[string]*Result),
	}
	extensionFilter := goflags.StringSlice{".jpg", ".png", ".gif", ".jpeg", ".ico", ".svg", ".css", ".js", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".exe", ".dll", ".msi", ".iso", ".img", ".bin", ".dat", ".dat", ".tmp", ".tmp", ".tmp", ".tmp", ".tmp"}
	options := &types.Options{
		MaxDepth:          3,             // Maximum depth to crawl
		FieldScope:        "rdn",         // Crawling Scope Field
		BodyReadSize:      math.MaxInt,   // Maximum response size to read
		Timeout:           10,            // Timeout is the time to wait for request in seconds
		Concurrency:       300,           // Concurrency is the number of concurrent crawling goroutines
		Parallelism:       300,           // Parallelism is the number of urls processing goroutines
		Delay:             0,             // Delay is the delay between each crawl requests in seconds
		RateLimit:         500,           // Maximum requests to send per second
		Strategy:          "depth-first", // Visit strategy (depth-first, breadth-first)
		ScrapeJSResponses: true,
		ExtensionFilter:   extensionFilter,
		IgnoreQueryParams: true,
		Headless:          true,
		// 过滤掉static
		OutOfScope: goflags.StringSlice{"static"},
		OnResult: func(result output.Result) {
			// 解析URL
			parsedURL, err := url.Parse(result.Request.URL)
			if err != nil {
				return
			}

			// 获取子域名
			subdomain := parsedURL.Hostname()

			// 更新结果
			crawlResult.Lock()

			// 初始化子域名结果
			if _, exists := crawlResult.Results[subdomain]; !exists {
				crawlResult.Results[subdomain] = &Result{
					URLs:      []string{},
					LoginURLs: []string{},
					Count:     0,
				}
			}

			// 检查是否已经达到500个页面
			if crawlResult.Results[subdomain].Count >= 500 {
				crawlResult.Unlock()
				return
			}

			// 添加URL
			crawlResult.Results[subdomain].URLs = append(crawlResult.Results[subdomain].URLs, result.Request.URL)

			// 检查是否为登录页面
			if utils.IsLoginPage(result.Response.Body) {
				crawlResult.Results[subdomain].LoginURLs = append(crawlResult.Results[subdomain].LoginURLs, result.Request.URL)
				gologger.Info().Msg("发现登录页面!")
			}

			// 更新计数器
			crawlResult.Results[subdomain].Count++

			crawlResult.Unlock()
		},
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msgf("初始化爬虫选项失败: %v", err)
	}
	defer crawlerOptions.Close()
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawler.Close()
	var input = "https://www.tsinghua.edu.cn/"
	err = crawler.Crawl(input)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
	}

	// 将结果序列化为JSON
	jsonData, err := json.MarshalIndent(crawlResult.Results, "", "  ")
	if err != nil {
		gologger.Fatal().Msgf("Failed to marshal JSON: %s", err.Error())
	}

	// 将JSON数据写入文件
	// 建议使用时间戳作为文件名的一部分
	// 生成时间戳
	timestamp := time.Now().Format("20060102150405")

	domain, err := url.Parse(input)
	if err != nil {
		gologger.Fatal().Msgf("Failed to parse URL: %s", err.Error())
	}

	filename := ""
	if domain != nil {
		// 构建文件名：域名_时间戳.json
		filename = fmt.Sprintf("%s_%s.json", domain.Hostname(), timestamp)
	} else {
		filename = fmt.Sprintf("default_%s.json", timestamp)
	}

	// 构建完整的文件路径
	fp := filepath.Join("results", filename)

	err = os.WriteFile(fp, jsonData, 0644)
	if err != nil {
		gologger.Fatal().Msgf("Failed to write JSON to file: %s", err.Error())
	}

	// 修正日志信息以匹配实际文件名
	gologger.Info().Msgf("Crawl results have been saved to %s", fp)
}
