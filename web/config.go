// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/goccy/go-yaml"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const DefaultConfigFile = "/etc/portitor/web.yaml"

// Config is /etc/portitor/web.yaml.
type Config struct {
	Bind string   `yaml:"bind"`
	DB   DBConfig `yaml:"db"`
	// JWTSecret signs session cookies. At least 32 characters.
	JWTSecret string `yaml:"jwt_secret"`
	// Dev serves the frontend from disk and drops the cookie Secure flag
	// (plain http://localhost). Never on a reachable address.
	Dev bool `yaml:"dev"`
	// TLSCert/TLSKey serve HTTPS directly; otherwise put a reverse proxy
	// in front.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
}

type DBConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
	SSLMode  string `yaml:"sslmode"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Bind == "" {
		cfg.Bind = "127.0.0.1:8080"
	}
	if cfg.DB.Port == 0 {
		cfg.DB.Port = 5432
	}
	if cfg.DB.SSLMode == "" {
		cfg.DB.SSLMode = "prefer"
	}
	if cfg.DB.Name == "" {
		cfg.DB.Name = "portitor"
	}
	return cfg, nil
}

func (c *Config) validateForServe() error {
	if len(c.JWTSecret) < 32 {
		return errors.New("jwt_secret must be at least 32 characters")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key go together")
	}
	return nil
}

func ConnectDB(c DBConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Name, c.SSLMode)
	// Not-found is a normal answer (lookups by name), not worth logging.
	lg := logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
	})
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: lg})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	return db, nil
}
