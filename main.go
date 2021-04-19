package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/whichxjy/cwebhook"
)

type Event struct {
	EventID string      `json:"event_id"`
	Topic   string      `json:"topic"`
	Data    interface{} `json:"data"`
}

func getSecret() string {
	return os.Getenv("SECRET")
}

func validateRequest(header *http.Header, body []byte) error {
	log.Printf("Get header: %+v\n", spew.Sdump(header))

	timestamp := header.Get("X-Hook-Timestamp")
	signature := header.Get("X-Hook-Signature")
	secret := getSecret()

	return cwebhook.Validate(signature, []byte(timestamp), body, []byte(secret))
}

func main() {
	r := gin.Default()
	r.POST("/events", func(c *gin.Context) {
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := validateRequest(&c.Request.Header, body); err != nil {
			log.Printf("Fail to validate request: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var event Event
		if err := json.Unmarshal(body, &event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		log.Printf("Get event: %+v\n", spew.Sdump(event))

		c.JSON(200, fmt.Sprintf("Got event %v", event.EventID))
	})
	_ = r.Run(":3000")
}
