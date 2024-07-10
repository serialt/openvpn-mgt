package main

import (
	"github.com/serialt/db/v3"
	"gorm.io/gorm"
)

type VPN struct {
	ID           int
	UserName     string
	CertName     string
	Version      int
	NotBefore    int
	NotAfter     int
	SerialNumber int
	Active       int
	DateGap      int
	CreateTime   int
}

func AutoMigrate() (gromdb *gorm.DB) {
	gromdb = db.New(config.DB)
	gromdb.AutoMigrate(&VPN{})
	return
}
