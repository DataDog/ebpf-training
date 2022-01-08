package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultPort    = "8080"
	maxPayloadSize = 10 * 1024 * 1024 // 10 MB
)

var (
	// source is a static, global rand object.
	source      *rand.Rand
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890~!@#$"
)

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[source.Intn(len(letterBytes))]
	}
	return string(b)
}

func init() {
	source = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// customResponse holds the requested size for the response payload.
type customResponse struct {
	Size int `json:"size"`
}

func postCustomResponse(context *gin.Context) {
	var customResp customResponse
	if err := context.BindJSON(&customResp); err != nil {
		_ = context.AbortWithError(http.StatusBadRequest, err)
		return
	}

	if customResp.Size > maxPayloadSize {
		_ = context.AbortWithError(http.StatusBadRequest, fmt.Errorf("requested size %d is bigger than max allowed %d", customResp, maxPayloadSize))
		return
	}

	context.JSON(http.StatusOK, map[string]string{"answer": randStringBytes(customResp.Size)})
}

func main() {
	engine := gin.New()

	engine.Use(gin.Recovery())
	engine.POST("/customResponse", postCustomResponse)

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	fmt.Printf("listening on 0.0.0.0:%s\n", port)
	if err := engine.Run(fmt.Sprintf("0.0.0.0:%s", port)); err != nil {
		log.Fatal(err)
	}
}
