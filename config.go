package main

import (
	"github.com/blinkbean/dingtalk"
	"gorm.io/gorm"
)

var (
	// 版本信息
	appVersion bool // 控制是否显示版本
	APPVersion = "v0.0.2"
	BuildTime  = "2006-01-02 15:04:05"
	GitCommit  = "xxxxxxxxxxx"
	ConfigFile = "config.yaml"
	config     *Config
	CreateUser string
	RevokeUser string

	AesKey     = "wzFdVviHTKraaPRWEa9bFLLzTkddtUNY"
	AesData    string // 用于存储明文
	DB         *gorm.DB
	bot        *dingtalk.DingTalk
	TIMEFORMAT = "20060102150405"
)

type Service struct {
	Host string `json:"host" yaml:"host"`
	Port string `json:"port" yaml:"port"`
}

type DingRobot struct {
	Token  string `yaml:"token"`
	Secret string `yaml:"secret"`
	Gap    int    `yaml:"gap"`
}
type EASYRSA struct {
	Version   int    `yaml:"version"`
	Dir       string `yaml:"dir"`
	CRLVerify string `yaml:"crlVerify"`
}

type Config struct {
	Service   Service   `json:"service" yaml:"service"`
	Encrypt   bool      `yaml:"encrypt"`
	Token     string    `yaml:"token"`
	DB        string    `yaml:"db"`
	EASYRSA   EASYRSA   `yaml:"easyRsa"`
	DingRobot DingRobot `yaml:"dingRobot"`
}
