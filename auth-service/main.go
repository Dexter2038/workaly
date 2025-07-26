package main

import (
	"context"
	"log"
	"net/http"
	"time"

	pb "auth-service/pb/userpb/proto"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type loginUser struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type registerUser struct {
	Name     string `json:"name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func register(c *gin.Context) {
	var user registerUser

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	res, err := grpcClient.Register(ctx, &pb.RegisterRequest{
		Name:     user.Name,
		Username: user.Username,
		Password: user.Password,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	if res.Status != pb.RegisterResponse_SUCCESS {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": res.Status.String(),
		})
		return
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"username": user.Username,
		"exp":      now.Add(time.Hour * 24).Unix(),
		"iat":      now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secure := true
	httpOnly := true
	c.SetCookie("token", token.Raw, 3600, "/", "", secure, httpOnly)

	c.JSON(http.StatusOK, gin.H{
		"message": "success",
	})
}

func login(c *gin.Context) {
	var user loginUser

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	res, err := grpcClient.Login(ctx, &pb.LoginRequest{
		Username: user.Username,
		Password: user.Password,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	if res.Status != pb.LoginResponse_SUCCESS {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": res.Status.String(),
		})
		return
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"username": user.Username,
		"exp":      now.Add(time.Hour * 24).Unix(),
		"iat":      now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secure := true
	httpOnly := true
	c.SetCookie("token", token.Raw, 3600, "/", "", secure, httpOnly)

	c.JSON(http.StatusOK, gin.H{
		"message": "success",
	})
}

var grpcClient pb.UserServiceClient

func main() {
	conn, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect to user-service: %v", err)
	}
	defer conn.Close()

	grpcClient = pb.NewUserServiceClient(conn)

	router := gin.Default()

	router.POST("/register", register)

	router.POST("/login", login)

	router.Run()
}
