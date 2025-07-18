package main

import (
	"event-booking-system/internal/database"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

// loginRequest represents the expected JSON structure for a login request
type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`    // User's email, required and must be a valid email
	Password string `json:"password" binding:"required,min=8"` // User's password, required and minimum 8 characters
}

// loginResponse represents the structure of the response after successful login
type loginResponse struct {
	Token  string `json:"token"`  // JWT token returned to the client
	UserId int    `json:"userId"` // The authenticated user's ID
}

// registerRequest represents the expected JSON structure for a user registration request
type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`    // User's email, required and must be valid
	Password string `json:"password" binding:"required,min=8"` // Password, required with minimum length of 8
	Name     string `json:"name" binding:"required,min=2"`     // User's full name, required with minimum 2 characters
}

// registerUser handles user registration requests
// It validates the input, hashes the password, creates a new user record in the database, and returns the created user.
func (app *application) registerUser(c *gin.Context) {
	var register registerRequest

	// Bind JSON input to the registerRequest struct and validate it
	if err := c.ShouldBindJSON(&register); err != nil {
		// If validation fails, return 400 Bad Request with error message
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the user's password securely using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(register.Password), bcrypt.DefaultCost)
	if err != nil {
		// If hashing fails, return 500 Internal Server Error
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Something went wrong"})
		return
	}

	// Replace the plain password with the hashed password
	register.Password = string(hashedPassword)

	// Create a new user object with the provided email, hashed password, and name
	user := database.User{
		Email:    register.Email,
		Password: register.Password,
		Name:     register.Name,
	}

	// Insert the new user record into the database
	err = app.models.Users.Insert(&user)
	if err != nil {
		// If insertion fails, return 500 Internal Server Error
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	// Return the created user object with HTTP status 201 Created
	c.JSON(http.StatusCreated, user)
}

// login authenticates a user by verifying credentials and returns a JWT token upon success
func (app *application) login(c *gin.Context) {
	var auth loginRequest

	// Bind JSON input to loginRequest struct and validate it
	if err := c.ShouldBindJSON(&auth); err != nil {
		// Return 400 Bad Request if validation fails
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Retrieve the user from the database by email
	existingUser, err := app.models.Users.GetByEmail(auth.Email)
	if existingUser == nil {
		// If no user found with this email, return 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// If database retrieval failed, return 500 Internal Server Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	// Compare hashed password with the password provided in the login request
	err = bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(auth.Password))
	if err != nil {
		// If password does not match, return 401 Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Create a new JWT token with userId claim and expiry of 72 hours
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": existingUser.Id,
		"expr":   time.Now().Add(time.Hour * 72).Unix(),
	})

	// Sign the token using the application's secret key
	tokenString, err := token.SignedString([]byte(app.jwtSecret))
	if err != nil {
		// Return 500 Internal Server Error if token generation fails
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	// Return the token and userId in the response with status 200 OK
	c.JSON(http.StatusOK, loginResponse{Token: tokenString, UserId: existingUser.Id})
}
