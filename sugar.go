package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"log/slog"

	"github.com/golang-module/carbon/v2"
	"github.com/serialt/lancet/cryptor"
	"github.com/serialt/lancet/fileutil"
	"github.com/spf13/cast"
)

func service() {
	slog.Debug("debug msg")
	slog.Info("info msg")
	slog.Error("error msg")
	DB = AutoMigrate()
	MigrateDirToDB(config.EASYRSA)
	Check()

}

func EnvGet(envName string, defaultValue string) (data string) {
	data = os.Getenv(envName)
	if len(data) == 0 {
		data = defaultValue
		return
	}
	return
}

func (c *Config) DecryptConfig() {
	if c.Encrypt {
		c.Token = cryptor.AesCbcDecryptBase64(c.Token, AesKey)
		slog.Debug(c.Token)
	}
}

func MigrateDirToDB(easyrsa EASYRSA) {
	var certsFileDir string
	switch easyrsa.Version {
	case 3:
		certsFileDir = easyrsa.Dir + "/pki/issued"
	case 2:
		certsFileDir = easyrsa.Dir + "/keys"
	}

	// crt file

	certs, err := fileutil.FileLoopFiles(certsFileDir)
	if err != nil {
		slog.Error("read cert failed", "cert_dir", certsFileDir)
	}

	var tmpCerts []string
	for _, v := range certs {
		if fileutil.Suffix(v) == ".crt" {
			tmpCerts = append(tmpCerts, v)
		}
	}
	certs = tmpCerts

	// 处理db中被注销的证书
	DisableUser(certs)
	// 兼容easyrsa v2

	crlSN, _ := ParseCRLSN(config.EASYRSA.CRLVerify)

	for _, v := range certs {
		_vpn, err := ParsePublicKey(v)
		if err != nil {
			slog.Error("parse cert failed", "error", err)
			continue
		}
		myuser := new(VPN)
		DB.Table("vpn").Where("cert_name = ?", _vpn.CertName).Scan(&myuser)
		if myuser.ID == 0 {
			DB.Table("vpn").Create(&_vpn)
		} else {
			// 修复历史数据
			if myuser.SerialNumber == 0 {
				DB.Table("vpn").Where("cert_name = ?", _vpn.CertName).Update("serial_number", _vpn.SerialNumber)
			} else {

				slog.Debug("user exits", "id", myuser.ID, "cert_name", _vpn.CertName)
			}

			// 如果用户的sn 被记录在crl中，这标记用户disable
			if slices.Contains(crlSN, _vpn.SerialNumber) {
				DB.Table("vpn").Where("cert_name = ?", _vpn.CertName).Update("active", 0)

			}
		}

	}

}

func ParseCRLSN(file string) (sn []int, err error) {
	crlData, err := os.ReadFile(file)
	if err != nil {
		return
	}

	block, _ := pem.Decode(crlData)
	if block == nil {
		slog.Error("Failed to decode PEM block containing CRL")
		return
	}
	crl, err := x509.ParseCRL(block.Bytes)
	if err != nil {
		slog.Error("parse crl failed", "error", err)
	}
	for _, v := range crl.TBSCertList.RevokedCertificates {
		_snTmp := fmt.Sprint(v.SerialNumber)
		_sn, _ := strconv.Atoi(_snTmp)
		sn = append(sn, _sn)

	}
	return
}

func ParsePublicKey(file string) (vpn *VPN, err error) {
	_vpn := &VPN{}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	slog.Debug("cert's cn", "cn", pub.Subject.CommonName)
	_vpn.CertName = fmt.Sprint(pub.Subject.CommonName)
	_vpn.UserName = _vpn.CertName
	_vpn.NotBefore = cast.ToInt(pub.NotBefore.Format(TIMEFORMAT))
	_vpn.NotAfter = cast.ToInt(pub.NotAfter.Format(TIMEFORMAT))
	_sn, _ := strconv.Atoi(fmt.Sprint(pub.SerialNumber))
	_vpn.SerialNumber = _sn

	_vpn.DateGap = int(carbon.Parse(pub.NotAfter.Format(TIMEFORMAT)).DiffAbsInDays(carbon.Parse(pub.NotBefore.Format(TIMEFORMAT))))
	_vpn.CreateTime = _vpn.NotBefore
	_vpn.Active = 1

	vpn = _vpn
	return
}

func Check() {
	var users []*VPN
	DB.Table("vpn").Where("active = ?", 1).Find(&users)

	for _, u := range users {
		_gap := int(carbon.Now().DiffInDays(carbon.Parse(cast.ToString(u.NotAfter))))
		if _gap < config.DingRobot.Gap && _gap > 0 {
			msg := fmt.Sprintf("vpn用户 %v id 为 %v 的证书 %v 到期时间还有 %v 天", u.UserName, u.ID, u.CertName, _gap)
			SendMSG(msg)
		} else if _gap < 3 {
			// 当证书过期三天，则标记该用户no active
			DB.Table("vpn").Where("id = ?", u.ID).Update("active", 0)
		}
	}

}

// 如果easyrsa注销了用户，则把数据库里对应的用户active标记为0.
func DisableUser(eCerts []string) {
	var certsName []string

	for _, v := range eCerts {
		_, _file := filepath.Split(v)
		_eCerts := strings.Split(_file, ".")
		certsName = append(certsName, _eCerts[0])
	}

	var allUsers []string
	DB.Table("vpn").Select("user_name").Where("active = ?", 1).Scan(&allUsers)
	for _, v := range allUsers {
		//  如果db里的用户在证书目录里找不到，则把该用户 active 字段标记为 0。
		if !slices.Contains(certsName, v) {
			DB.Table("vpn").Where("user_name = ?", v).Update("active", 0)
			slog.Info("该用户已经被标记注销", "username", v)
		}
	}

}

func SendMSG(msg string) {
	bot.SendTextMessage(msg)
}

func CreateOpenVPNUser() {

	switch config.EASYRSA.Version {
	case 3:

	case 2:
	}
}
