package main

import (
	"flag"
	"fmt"

	"log/slog"

	"github.com/blinkbean/dingtalk"
	"github.com/serialt/lancet/cryptor"
	"github.com/serialt/sugar/v3"
)

func init() {
	flag.BoolVar(&appVersion, "v", false, "Display build and version messages")
	flag.StringVar(&ConfigFile, "c", "config.yaml", "Config file")
	flag.StringVar(&AesData, "d", "", "Plaintext for encryption")
	flag.StringVar(&CreateUser, "user", "", "create user for openvpn")
	flag.StringVar(&RevokeUser, "revoke", "", "revoke user for openvpn")
	flag.Parse()

	err := sugar.LoadConfig(ConfigFile, &config)
	if err != nil {
		config = new(Config)
	}
	slog.SetDefault(sugar.New(sugar.WithLevel("debug")))
	config.DecryptConfig()
	bot = dingtalk.InitDingTalkWithSecret(config.DingRobot.Token, config.DingRobot.Secret)

}
func main() {
	if appVersion {
		fmt.Printf("APPVersion: %v  BuildTime: %v  GitCommit: %v\n",
			APPVersion,
			BuildTime,
			GitCommit)
		return
	}
	if len(AesData) > 0 {
		fmt.Printf("Encrypted string: %v\n", cryptor.AesCbcEncryptBase64(AesData, AesKey))
		fmt.Printf("Plaintext : %v\n", cryptor.AesCbcDecryptBase64(cryptor.AesCbcEncryptBase64(AesData, AesKey), AesKey))
		return
	}
	service()
}
