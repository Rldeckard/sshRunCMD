package main

import (
	"log"

	"github.com/neteng-tools/aesGenerate256"
	"github.com/spf13/viper"
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
	if len(appCode) == 0 {
		appCode = aes256.Random32ByteString()
		viper.Set("helper.key", appCode)
		err := viper.WriteConfigAs("key.yml")
   	 	if err != nil {
      	  log.Fatalf("Error writing config file: %v", err)
    	}
		// prevents the key from being duplicated into the regular config file
		viper.Set("helper.key", "unused")

	}
	viper.SetConfigName("helper") // Change file and reread contents.
	err = viper.ReadInConfig()
	if err != nil {
		log.Println(err)
	}

	if len(viper.GetString("helper.username")) > 0 {
		cred.username, _ = aes256.Decrypt(appCode, viper.GetString("helper.username"))
	}
	if len(viper.GetString("helper.password")) > 0 {
		cred.password, _ = aes256.Decrypt(appCode, viper.GetString("helper.password"))
	}
	if len(viper.GetString("helper.fallbackUser")) > 0 {
		cred.fallbackUser, _ = aes256.Decrypt(appCode, viper.GetString("helper.fallbackUser"))
	}
	if len(viper.GetString("helper.fallbackPass")) > 0 {
		cred.fallbackPass, _ = aes256.Decrypt(appCode, viper.GetString("helper.fallbackPass"))
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
	if viper.GetInt("helper.threads") > 0 {
		cred.threads = viper.GetInt("helper.threads")
	} else {
		cred.threads = 6
	}
	if len(viper.GetString("helper.core")) > 0 {
		cred.core = viper.GetString("helper.core")
	} else {
		cred.core = ""
	}

	return true
}
