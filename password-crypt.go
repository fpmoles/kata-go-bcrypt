package crytpo

import (
	"github.com/riptano/cloud/graphql/errors"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
)

type Algorithm string

const (
	Algorithm_Bcrypt Algorithm = "bcrypt"
	DEFAULT_COST_KEY           = "BCRYPT_COST"
)

//HashPassword creates a cryptographically secure hash of a password
func HashPassword(password string, algorithm Algorithm) ([]byte, error) {
	passwordByte := []byte(password)
	cost, err := getCost()
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case Algorithm_Bcrypt:
		return performBcryptHash(passwordByte, cost)
	}
	return nil, errors.New("algorithm not implemented")
}

//VerifyHash takes a password and a hash and compares that the password would generate the hash
func VerifyHash(password string, hash []byte, algorithm Algorithm) (bool, error) {
	passwordByte := []byte(password)
	switch algorithm {
	case Algorithm_Bcrypt:
		return verifyBcryptHash(hash, passwordByte), nil
	}
	return false, errors.New("algorithm not implemented")
}

func performBcryptHash(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

func verifyBcryptHash(hashedPassword []byte, passwordByte []byte) bool {
	err := bcrypt.CompareHashAndPassword(hashedPassword, passwordByte)
	if err == nil {
		return true
	}
	return false
}

func getCost() (int, error) {
	if value, ok := os.LookupEnv(DEFAULT_COST_KEY); ok {
		return strconv.Atoi(value)
	}
	return 10, nil
}
