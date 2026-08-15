package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 19 * 1024
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLength  = 16
	argonKeyLength   = 32
	argonMaxMemory   = 256 * 1024
	argonMaxTime     = 10
	argonMaxParallel = 16
	minimumPassword  = 12
	maximumPassword  = 1024
)

var errInvalidPasswordHash = errors.New("invalid password hash")

func HashPassword(password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey(
		[]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parameters, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		consumePasswordWork(password)
		return false
	}
	actual := argon2.IDKey(
		[]byte(password), salt, parameters.iterations, parameters.memory,
		parameters.parallelism, uint32(len(expected)),
	)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func consumePasswordWork(password string) {
	argon2.IDKey(
		[]byte(password), make([]byte, argonSaltLength),
		argonIterations, argonMemory, argonParallelism, argonKeyLength,
	)
}

type passwordParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parsePasswordHash(encoded string) (passwordParameters, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	memory, err := parseUint32Parameter(parameters[0], "m=")
	if err != nil {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	iterations, err := parseUint32Parameter(parameters[1], "t=")
	if err != nil {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	parallelismValue, err := parseUint32Parameter(parameters[2], "p=")
	if err != nil || parallelismValue > 255 {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	parallelism := uint8(parallelismValue)
	if memory < argonMemory || memory > argonMaxMemory ||
		iterations < argonIterations || iterations > argonMaxTime ||
		parallelism == 0 || parallelism > argonMaxParallel {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) != argonKeyLength {
		return passwordParameters{}, nil, nil, errInvalidPasswordHash
	}
	return passwordParameters{memory: memory, iterations: iterations, parallelism: parallelism}, salt, hash, nil
}

func parseUint32Parameter(value, prefix string) (uint32, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errInvalidPasswordHash
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	return uint32(parsed), err
}

func validatePassword(password string) error {
	length := len(password)
	if length < minimumPassword {
		return fmt.Errorf("password must contain at least %d bytes", minimumPassword)
	}
	if length > maximumPassword {
		return fmt.Errorf("password must contain no more than %d bytes", maximumPassword)
	}
	return nil
}
