package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func getPrice(c *gin.Context) {
	itemName := c.Param("itemName")
	if itemName == "" {
		log.Printf("Missing item name parameter")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	log.Printf("Retrieving the price for items with name: %s", itemName)
	prices, err := Read(itemName)
	if err != nil {
		log.Printf("Failed to read price for %s", itemName)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, prices)
}

func getListPrices(c *gin.Context) {
	var itemNames []string
	err := c.ShouldBindBodyWithJSON(itemNames)
	if err != nil {
		log.Printf("Request body in wrong format: %s", err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	log.Printf("Retrieving the price for items with name: %v", itemNames)
	prices, err := ReadList(itemNames)
	if err != nil {
		log.Printf("Failed to read price for %v", itemNames)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, prices)
}

// ------------------------------------------------------------
// The main function
// ------------------------------------------------------------

func SetupRouter(cfg Config) *gin.Engine {
	gin.SetMode(gin.DebugMode)

	router := gin.Default()
	// authentication.Setup(cfg)

	// ------------- Handling Account Creation and Login ---------------

	// Independent of API version, therefore not in the auth bracket
	// router.POST("/v1/users", authentication.CreateAccount)
	// JWT BASED AUTHENTICATION
	// router.POST("/v1/users/:userId/login", authentication.Login)

	// ------------- Handling Routes v1 (API version 1) ---------------

	// Add authentication middleware to v1 router
	authorized := router.Group("/v1")
	authorized.Use(AuthenticationMiddleware(cfg))
	{
		authorized.GET("/price/:itemName", getPrice)
		authorized.GET("/price/list", getListPrices)
	}

	return router
}

func Start(cfg Config) error {
	router := SetupRouter(cfg)

	// -------------------------------------------

	address := cfg.ListenAddr + ":" + cfg.ListenPort
	// Only allow TLS
	var err error
	if !cfg.DisableTLS {
		err = router.RunTLS(address, cfg.TLSCertificate, cfg.TLSKeyfile)
	} else {
		log.Printf("Disabling TLS...")
		err = router.Run(address)
	}
	return err
}
