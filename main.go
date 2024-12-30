package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// Result 结果结构体
type Result struct {
	URLs      []string `json:"url"`
	LoginURLs []string `json:"login_url"`
	Count     int      `json:"count"`
}

// CrawlResult 爬虫结果
type CrawlResult struct {
	sync.RWMutex
	Results map[string]*Result
}

// IsLoginPageDynamic 登录页面检测
func IsLoginPageDynamic(page *rod.Page) bool {
	// 等待页面加载完成
	err := page.WaitLoad()
	if err != nil {
		return false
	}

	// 等待页面稳定
	time.Sleep(2 * time.Second)

	// 检查密码输入框
	hasPassword := false
	passwordSelectors := []string{
		"input[type='password']",
		"input[name*='pass']",
		"input[id*='pass']",
		"input[name*='pwd']",
		"input[id*='pwd']",
	}

	for _, selector := range passwordSelectors {
		elements, err := page.Elements(selector)
		if err == nil && len(elements) > 0 {
			hasPassword = true
			gologger.Debug().Msgf("找到密码框: %s", selector)
			break
		}
	}

	if !hasPassword {
		return false
	}

	// 检查用户名输入框
	hasUsername := false
	usernameSelectors := []string{
		"input[type='text']",
		"input[type='email']",
		"input[name*='username']",
		"input[id*='username']",
		"input[name*='userid']",
		"input[id*='userid']",
		"input[name*='email']",
		"input[id*='email']",
		"input[name*='account']",
		"input[id*='account']",
	}

	for _, selector := range usernameSelectors {
		elements, err := page.Elements(selector)
		if err == nil && len(elements) > 0 {
			hasUsername = true
			gologger.Debug().Msgf("找到用户名输入框: %s", selector)
			break
		}
	}

	// 如果找到了登录表单的关键元素，记录日志
	if hasPassword && hasUsername {
		info, err := page.Info()
		if err == nil {
			gologger.Debug().Msgf("发现完整登录表单: %s", info.URL)
		}
	}

	return hasPassword && hasUsername
}

func main() {
	// 初始化日志
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	crawlResult := &CrawlResult{
		Results: make(map[string]*Result),
	}

	// 设置要过滤的文件扩展名
	extensionFilter := goflags.StringSlice{
		".jpg", ".png", ".gif", ".jpeg", ".ico", ".svg",
		".css", ".js", ".woff", ".woff2", ".eot", ".ttf", ".otf",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
		".exe", ".dll", ".msi", ".iso", ".img", ".bin", ".dat",
	}

	// 修改浏览器实例的创建方式，增加更多选项
	browser := rod.New().
		Timeout(60 * time.Second).
		MustConnect()

	defer browser.MustClose()

	// 创建一个 WaitGroup 来等待所有 goroutine 完成
	var wg sync.WaitGroup

	options := &types.Options{
		MaxDepth:          3,               // 最大爬取深度
		FieldScope:        "rdn",           // 爬取范围
		BodyReadSize:      math.MaxInt,     // 最大响应大小
		Timeout:           30,              // 请求超时时间(秒)
		Concurrency:       300,             // 并发爬取协程数
		Parallelism:       300,             // URL处理并发数
		Delay:             0,               // 请求间隔(秒)
		RateLimit:         500,             // 每秒最大请求数
		Strategy:          "breadth-first", // 访问策略(广度优先)
		ScrapeJSResponses: true,            // 抓取JS响应
		ExtensionFilter:   extensionFilter,
		IgnoreQueryParams: true,
		Headless:          true,
		OutOfScope:        goflags.StringSlice{"static", "assets", "img"}, // 扩展排除范围

		OnResult: func(result output.Result) {
			// 添加调试日志
			gologger.Debug().Msgf("正在处理URL: %s", result.Request.URL)

			parsedURL, err := url.Parse(result.Request.URL)
			if err != nil {
				gologger.Debug().Msgf("URL解析错误: %v", err)
				return
			}

			subdomain := parsedURL.Hostname()

			crawlResult.Lock()
			if _, exists := crawlResult.Results[subdomain]; !exists {
				crawlResult.Results[subdomain] = &Result{
					URLs:      []string{},
					LoginURLs: []string{},
					Count:     0,
				}
			}

			// 检查是否达到URL限制
			if crawlResult.Results[subdomain].Count >= 500 {
				crawlResult.Unlock()
				return
			}

			// 直接添加URL和更新计数
			crawlResult.Results[subdomain].URLs = append(crawlResult.Results[subdomain].URLs, result.Request.URL)
			crawlResult.Results[subdomain].Count++
			crawlResult.Unlock()

			// 在启动 goroutine 前增加计数
			wg.Add(1)
			go func() {
				defer wg.Done()

				// 设置超时上下文
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				// 创建页面
				page, err := browser.Page(proto.TargetCreateTarget{URL: result.Request.URL})
				if err != nil {
					gologger.Debug().Msgf("创建页面错误: %v", err)
					return
				}
				defer page.Close()

				// 使用带超时的通道来控制检测过程
				select {
				case <-ctx.Done():
					gologger.Debug().Msgf("页面检测超时: %s", result.Request.URL)
					return
				default:
					if IsLoginPageDynamic(page) {
						crawlResult.Lock()
						crawlResult.Results[subdomain].LoginURLs = append(
							crawlResult.Results[subdomain].LoginURLs,
							result.Request.URL,
						)
						crawlResult.Unlock()
						gologger.Info().Msgf("发现登录页面: %s", result.Request.URL)
					}
				}
			}()
		},
	}

	// 初始化爬虫选项
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msgf("初始化爬虫选项失败: %v", err)
	}
	defer crawlerOptions.Close()

	// 创建爬虫实例
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawler.Close()

	// 设置起始URL并开始爬取
	var input = "https://www.hsbc.com.cn/"
	err = crawler.Crawl(input)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
	}

	// 等待所有 goroutine 完成后再输出信息
	wg.Wait()
	gologger.Info().Msgf("所有登录页面检测完成")

	// 将结果序列化为JSON
	jsonData, err := json.MarshalIndent(crawlResult.Results, "", "  ")
	if err != nil {
		gologger.Fatal().Msgf("Failed to marshal JSON: %s", err.Error())
	}

	// 生成时间戳
	timestamp := time.Now().Format("20060102150405")

	// 解析域名用于文件名
	domain, err := url.Parse(input)
	if err != nil {
		gologger.Fatal().Msgf("Failed to parse URL: %s", err.Error())
	}

	// 构建文件名
	filename := ""
	if domain != nil {
		filename = fmt.Sprintf("%s_%s.json", domain.Hostname(), timestamp)
	} else {
		filename = fmt.Sprintf("default_%s.json", timestamp)
	}

	// 确保results目录存在
	err = os.MkdirAll("results", 0755)
	if err != nil {
		gologger.Fatal().Msgf("Failed to create results directory: %s", err.Error())
	}

	// 构建完整的文件路径
	fp := filepath.Join("results", filename)

	// 写入文件
	err = os.WriteFile(fp, jsonData, 0644)
	if err != nil {
		gologger.Fatal().Msgf("Failed to write JSON to file: %s", err.Error())
	}

	gologger.Info().Msgf("爬虫结果已保存到: %s", fp)
}
