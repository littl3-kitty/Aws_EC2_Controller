package core

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/littl3-kitty/Aws_EC2_Controller/internal/crypto"
)

type ConfigManager struct {
	configDir  string
	configFile string
	crypto     *crypto.CryptoManager
}

type storedCredentials struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func NewConfigManager() *ConfigManager {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".aws_ctrl")
	
	os.MkdirAll(configDir, 0755)
	
	return &ConfigManager{
		configDir:  configDir,
		configFile: filepath.Join(configDir, "credentials.enc"),
		crypto:     crypto.NewCryptoManager(),
	}
}

func (c *ConfigManager) SaveCredentials(accessKey, secretKey string) error {
	encAccessKey, err := c.crypto.Encrypt(accessKey)
	if err != nil {
		return err
	}

	encSecretKey, err := c.crypto.Encrypt(secretKey)
	if err != nil {
		return err
	}

	creds := storedCredentials{
		AccessKey: encAccessKey,
		SecretKey: encSecretKey,
	}

	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return os.WriteFile(c.configFile, data, 0600)
}

func (c *ConfigManager) LoadCredentials() (string, string, error) {
	data, err := os.ReadFile(c.configFile)
	if err != nil {
		return "", "", err
	}

	var creds storedCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return "", "", err
	}

	accessKey, err := c.crypto.Decrypt(creds.AccessKey)
	if err != nil {
		return "", "", err
	}

	secretKey, err := c.crypto.Decrypt(creds.SecretKey)
	if err != nil {
		return "", "", err
	}

	return accessKey, secretKey, nil
}

func (c *ConfigManager) HasSavedCredentials() bool {
	_, err := os.Stat(c.configFile)
	return err == nil
}
