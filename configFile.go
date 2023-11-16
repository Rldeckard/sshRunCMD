package main

import (
	"github.com/Rldeckard/aesGenerate256/authGen"
	"github.com/spf13/viper"
	"log"
)

// Reads username and password from config files and defines them inside the CMD type.
func GetCredentialsFromFiles(cred *CRED) bool {
	viper.AddConfigPath(".")
	viper.SetConfigName("key") // Register config file name (no extension)
	viper.SetConfigType("yml") // Look for specific type
	var err = viper.ReadInConfig()
	if err != nil {
		log.Println(err)
	}
	appCode = viper.GetString("helper.key")

	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	if err != nil {
		log.Println(err)
	}

	if len(viper.GetString("helper.username")) > 0 {
		cred.username = aes256.Decrypt(appCode, viper.GetString("helper.username"))
	}
	if len(viper.GetString("helper.password")) > 0 {
		cred.password = aes256.Decrypt(appCode, viper.GetString("helper.password"))
	}
	if len(viper.GetString("helper.fallbackUser")) > 0 {
		cred.fallbackUser = aes256.Decrypt(appCode, viper.GetString("helper.fallbackUser"))
	}
	if len(viper.GetString("helper.fallbackPass")) > 0 {
		cred.fallbackPass = aes256.Decrypt(appCode, viper.GetString("helper.fallbackPass"))
	}
	if viper.GetInt("blockTimer.pingCount") > 0 {
		cred.pingCount = viper.GetInt("blockTimer.pingCount")
	} else {
		cred.pingCount = 3 //repeat
	}
	if viper.GetInt("blockTimer.pingTimeout") > 0 {
		cred.pingTimeout = viper.GetInt("blockTimer.pingTimeout")
	} else {
		cred.pingTimeout = 500 //ms
	}
	if len(viper.GetString("helper.core")) > 0 {
		cred.core = viper.GetString("helper.core")
	} else {
		cred.core = ""
	}

	return true
}
