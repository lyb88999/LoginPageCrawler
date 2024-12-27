package utils

import (
	"github.com/projectdiscovery/gologger"
	"regexp"
	"strings"
)

// LoginPageIndicators 登录页面可能包含的特征
type LoginPageIndicators struct {
	FormAttributes  []string
	InputTypes      []string
	ButtonTexts     []string
	KeywordPatterns []string
	ExcludePatterns []string
}

// 初始化登录页面特征
var loginIndicators = LoginPageIndicators{
	FormAttributes: []string{
		"login",
		"signin",
		"sign-in",
		"logon",
		"authenticate",
	},
	InputTypes: []string{
		"password",
		"text",
		"email",
		"tel",
	},
	ButtonTexts: []string{
		"登录",
		"登陆",
		"sign in",
		"signin",
		"login",
		"log in",
		"submit",
		"确定",
		"提交",
	},
	KeywordPatterns: []string{
		"用户名",
		"账号",
		"account",
		"username",
		"密码",
		"password",
		"登录",
		"login",
		"signin",
		"sign in",
		"sign-in",
	},
	ExcludePatterns: []string{
		"注册",
		"register",
		"signup",
		"忘记密码",
		"找回密码",
	},
}

func IsLoginPage(body string) bool {
	bodyLower := strings.ToLower(body)

	// 1. 必须包含表单元素
	if !strings.Contains(bodyLower, "<form") {
		return false
	}

	// 2. 必须包含密码输入框
	if !strings.Contains(bodyLower, "type=\"password\"") {
		return false
	}

	// 3. 评分系统
	score := 0

	// 检查表单属性
	for _, attr := range loginIndicators.FormAttributes {
		if strings.Contains(bodyLower, attr) {
			score += 2
		}
	}

	// 检查输入框类型
	inputTypeCount := 0
	for _, inputType := range loginIndicators.InputTypes {
		if strings.Contains(bodyLower, "type=\""+inputType+"\"") {
			inputTypeCount++
		}
	}
	if inputTypeCount >= 2 {
		score += 3
	}

	// 检查按钮文本
	for _, buttonText := range loginIndicators.ButtonTexts {
		if strings.Contains(bodyLower, buttonText) {
			score += 2
		}
	}

	// 检查关键词
	keywordCount := 0
	for _, pattern := range loginIndicators.KeywordPatterns {
		if strings.Contains(bodyLower, pattern) {
			keywordCount++
		}
	}
	score += keywordCount

	// 检查排除模式（如果仅仅是注册页面或找回密码页面，应该排除）
	excludeCount := 0
	for _, pattern := range loginIndicators.ExcludePatterns {
		if strings.Contains(bodyLower, pattern) {
			excludeCount++
		}
	}

	// 如果排除模式出现次数过多，可能是注册页面
	if excludeCount > 2 {
		score -= 3
	}

	// 使用正则表达式检查表单结构
	formRegex := regexp.MustCompile(`<form[^>]*>[\s\S]*?<input[^>]*type=["']password["'][^>]*>[\s\S]*?</form>`)
	if formRegex.MatchString(bodyLower) {
		score += 3
	}

	// 检查是否包含验证码相关元素（可选）
	if strings.Contains(bodyLower, "captcha") || strings.Contains(bodyLower, "验证码") {
		score += 1
	}

	// 记录详细日志
	gologger.Debug().Msgf("Login page detection score: %d for URL", score)

	// 根据得分判断是否为登录页面
	return score >= 6
}
