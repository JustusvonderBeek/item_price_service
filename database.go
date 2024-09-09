package main

import (
	"database/sql"
	"log"

	"github.com/go-sql-driver/mysql"
)

var dbConfig DBConfig
var db *sql.DB

type DBConfig struct {
	DBUser      string
	DBPwd       string
	Addr        string
	NetworkType string
	DBName      string
}

func CheckDatabaseOnline(config DBConfig) {
	mysqlCfg := mysql.Config{
		User:                 config.DBUser,
		Passwd:               config.DBPwd,
		Net:                  config.NetworkType,
		Addr:                 config.Addr,
		DBName:               config.DBName,
		AllowNativePasswords: true,
		CheckConnLiveness:    true,
		ParseTime:            true,
	}
	var err error
	configString := mysqlCfg.FormatDSN()
	// log.Printf("Config string: %s", configString)
	db, err = sql.Open("mysql", configString)
	if err != nil {
		log.Fatalf("Cannot connect to database: %s", err)
	}
	_, pingErr := db.Exec("select 42")
	if pingErr != nil {
		log.Fatalf("Database not responding: %s", pingErr)
	}
	log.Print("Connected to database")
}

type Price struct {
	Url           string
	Article       string
	Price         string
	OriginalPrice string
	KiloPrice     string
	Retailer      string
}

const priceTable = "prices"

// ---------------------------------------------
// Retrieving
// ---------------------------------------------

func Read(item string) ([]Price, error) {
	if item == "" {
		log.Print("Not answering empty search string")
		return []Price{}, nil
	}
	// Read the information for matching items from the database
	// and return them here
	query := "SELECT url,article,price,original_price,kilo_price,retailer FROM " + priceTable + " WHERE INSTR(article, '" + item + "') > 0"
	// query := "SELECT url,article,price,original_price,kilo_price,retailer FROM " + priceTable + " WHERE DIFFERENCE(article, '" + item + "') > 2"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Failed to query items with %s from database: %s", item, err)
		return []Price{}, err
	}
	defer rows.Close()
	// Looping through data, assigning the columns to the given struct
	var prices []Price
	for rows.Next() {
		var price Price
		if err := rows.Scan(&price.Url, &price.Article, &price.Price, &price.OriginalPrice, &price.KiloPrice, &price.Retailer); err != nil {
			return []Price{}, err
		}
		prices = append(prices, price)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Failed to retrieve items from database: %s", err)
		return []Price{}, err
	}
	return prices, nil
}

func ReadList(items []string) ([]Price, error) {
	log.Printf("Returning price for %d items", len(items))
	if len(items) == 0 {
		return []Price{}, nil
	}
	var prices []Price
outer:
	for _, item := range items {
		query := "SELECT url,article,price,original_price,kilo_price,retailer FROM " + priceTable + " WHERE INSTR(article, '" + item + "') > 0"
		// query := "SELECT url,article,price,original_price,kilo_price,retailer FROM " + priceTable + " WHERE DIFFERENCE(article, '" + item + "') > 2"
		rows, err := db.Query(query)
		if err != nil {
			log.Printf("Failed to query items with %s from database: %s", item, err)
			return []Price{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var price Price
			if err := rows.Scan(&price.Url, &price.Article, &price.Price, &price.OriginalPrice, &price.KiloPrice, &price.Retailer); err != nil {
				continue outer
			}
			prices = append(prices, price)
		}
		if err := rows.Err(); err != nil {
			log.Printf("Failed to retrieve items from database: %s", err)
			return []Price{}, err
		}
	}
	return prices, nil
}
