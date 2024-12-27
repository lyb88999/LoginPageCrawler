package utils

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestIsLogin(t *testing.T) {
	// 读取login.html页面的内容
	file, err := os.Open("login.html")
	defer file.Close()
	if err != nil {
		t.Fatal(err)
		return
	}
	var contentBuilder strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		contentBuilder.WriteString(scanner.Text())
		contentBuilder.WriteString("\n")
	}
	if err = scanner.Err(); err != nil {
		t.Log(err)
		return
	}
	fileContent := contentBuilder.String()
	bodyLower := strings.ToLower(fileContent)
	if strings.Contains(bodyLower, "<form") && strings.Contains(bodyLower, "type=\"password\"") {
		t.Log("是登录页面")
	}

}
