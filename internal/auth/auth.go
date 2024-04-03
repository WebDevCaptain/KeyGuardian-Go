// Authentication
package auth

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Password []byte
}

func CreateUser(username, password string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		Username: username,
		Password: hashedPassword,
	}

	return user, nil
}

func AuthenticateUser(user *User, password string) bool {
	err := bcrypt.CompareHashAndPassword(user.Password, []byte(password))
	return err == nil
}
