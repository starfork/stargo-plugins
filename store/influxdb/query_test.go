package influxdb

import (
	"fmt"
	"testing"
	"time"
)

func TestBuildTime(t *testing.T) {
	loc := "Asia/Shanghai"
	l, _ := time.LoadLocation(loc) // 设置为中国上海时区（UTC+8）

	fmt.Println(l, "build e.l")
	fmt.Println(time.Unix(0, 0).UTC().In(l))
}
